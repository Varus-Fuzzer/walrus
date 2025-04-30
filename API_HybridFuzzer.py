#!/usr/bin/env python3
import os
import sys
import json
import time
import random
import subprocess
import argparse
import threading
import queue
import logging
import requests
import struct
import re
import hashlib
import signal
import tempfile
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class HybridFuzzer:
    """
    Hybrid Fuzzer that uses LibFuzzer + LLM to generate WAT (WebAssembly Text) inputs.
    Modified to use Gemini API with free tier usage limits.
    """

    def __init__(
        self,
        target_path: str,
        corpus_dir: str,
        libfuzzer_options: dict = None,
        llm_model: str = "gemini-1.5-pro",  # 기본값을 Gemini로 변경
        llm_temperature: float = 0.7,
        libfuzzer_cycles: int = 1,
        llm_cycles: int = 1,
        gemini_api_key: str = None,  # Gemini API 키 추가
        confirm_requests: bool = False,  # API 요청 전 확인 요청 옵션
        free_tier_only: bool = True,  # 무료 티어만 사용
    ):
        self.target_path = os.path.abspath(target_path)
        self.corpus_dir = os.path.abspath(corpus_dir)
        self.crashes_dir = os.path.join(os.path.dirname(self.corpus_dir), "crashes")
        self.libfuzzer_options = libfuzzer_options or {}
        self.llm_model = llm_model
        self.llm_temperature = llm_temperature
        self.llm_cycles = llm_cycles
        self.gemini_api_key = gemini_api_key or os.environ.get("GEMINI_API_KEY")
        self.confirm_requests = confirm_requests
        self.free_tier_only = free_tier_only
        self.last_coverage = 0  # 마지막으로 기록된 커버리지
        self.last_coverage_change_time = time.time()  # 마지막 커버리지 변화 시간
        self.last_llm_call_time = time.time()  # 마지막 LLM 호출 시간
        self.coverage_stagnation_threshold = 60  # 커버리지 정체 판단 기준 (10분 = 600초)
        self.llm_call_interval = 300  # LLM 호출 간격 (10분 = 600초)

        # Gemini 무료 티어 제한
        # 참고: 실제 최신 무료 티어 제한 확인 필요
        self.free_tier_limits = {
            "daily_requests": 60,  # 하루 최대 요청 수
            "per_min": 10,          # 분당 최대 요청 수
            "reset_time": datetime.now() + timedelta(days=1)  # 다음 리셋 시간
        }

        # API 사용량 추적을 위한 변수
        self.api_usage = {
            "daily_count": 0,
            "last_request_time": None, 
            "minute_requests": [],  # 각 요청 시간 기록 (분당 제한 관리용)
        }

        # 지속적인 퍼징을 위한 변수들
        self.libfuzzer_process = None
        self.libfuzzer_process_lock = threading.Lock()
        self.keep_running = True  # 프로세스 관리를 위한 플래그

        self.corpus_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.stats_lock = threading.Lock()
        
        # WAT 컴파일 에러 피드백을 위한 변수
        self.wat_error_history = []  # 최근 에러들을 저장
        self.max_error_history = 3   # 최대 저장할 에러 수

        os.makedirs(self.corpus_dir, exist_ok=True)
        os.makedirs(self.crashes_dir, exist_ok=True)

        # Gemini API 키 확인
        if not self.gemini_api_key:
            logger.error("[INIT] Gemini API key not found. Please set GEMINI_API_KEY environment variable or provide it as an argument.")
            logger.warning("LLM features will be disabled.")
            self.llm_cycles = 0
        else:
            logger.info(f"[INIT] Using {self.llm_model} model for WAT generation")

            # API 연결 테스트
            try:
                response = self._test_gemini_connection()
                if response:
                    logger.info(f"[INIT] Successfully connected to Gemini API")
                else:
                    logger.warning(f"[INIT] Failed to connect to Gemini API")
                    logger.warning("LLM features will be disabled.")
                    self.llm_cycles = 0
            except Exception as e:
                logger.error(f"[INIT] Gemini API connection error: {e}")
                logger.warning("LLM features will be disabled.")
                self.llm_cycles = 0

        self.stats = {
            "libfuzzer_runs": 0,
            "llm_runs": 0,
            "total_execs": 0,
            "crashes_found": 0,
            "coverage": 0,
            "start_time": time.time(),
            "total_time": 0,
            "corpus_size": 0,
            "crashes_count": 0,
            # 추가 통계 항목
            "wat_compile_errors": 0,
            "wat_compile_success": 0,
            "recent_new_coverage": [],  # 최근 발견된 커버리지 정보
            "api_requests": 0,
            "api_free_tier_limit": self.free_tier_limits["daily_requests"],
            "api_requests_remaining": self.free_tier_limits["daily_requests"]
        }

    def _test_gemini_connection(self):
        """Gemini API 연결을 테스트합니다."""
        try:
            # 디버깅 메시지 추가
            logger.debug(f"[INIT] Testing Gemini API connection with key: {self.gemini_api_key[:4]}...")
            
            headers = {
                "x-goog-api-key": self.gemini_api_key,
                "Content-Type": "application/json"
            }
            
            # 테스트용 간단한 요청 데이터
            data = {
                "contents": [
                    {
                        "parts": [
                            {"text": "Hello, are you available?"}
                        ]
                    }
                ],
                "generationConfig": {
                    "temperature": 0.2,
                    "maxOutputTokens": 10
                }
            }
            
            # 모델 이름 처리 - 이 부분이 문제였음
            # 점을 하이픈으로 잘못 바꿨던 부분을 제거
            model_name = self.llm_model  # 모델 이름을 그대로 사용
            
            # URL 구성
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent"
            logger.debug(f"[INIT] API test URL: {url}")
            
            # 요청 전송
            response = requests.post(
                url,
                headers=headers,
                json=data,
                timeout=10  # 타임아웃 증가
            )
            
            # 응답 상태 코드 확인
            if response.status_code != 200:
                logger.error(f"[INIT] API test failed with status code: {response.status_code}")
                logger.error(f"[INIT] Response: {response.text}")
                return False
            
            # 응답 내용 확인 (디버깅용)
            logger.debug(f"[INIT] API test response: {response.status_code}")
            logger.debug(f"[INIT] Response body: {response.text[:100]}...")
            
            return True
            
        except Exception as e:
            logger.error(f"[INIT] Failed to connect to Gemini API: {e}")
            # 더 자세한 오류 정보 출력
            import traceback
            logger.debug(f"[INIT] Connection error trace: {traceback.format_exc()}")
            return False

    def _check_api_limits(self):
        """
        API 사용량을 체크하고 무료 티어 한도 내에 있는지 확인합니다.
        """
        now = datetime.now()
        
        # 일일 한도 초기화 시간 체크
        if now >= self.free_tier_limits["reset_time"]:
            logger.info("[LLM] Daily API limit reset")
            self.api_usage["daily_count"] = 0
            self.free_tier_limits["reset_time"] = now + timedelta(days=1)
            
            with self.stats_lock:
                self.stats["api_requests_remaining"] = self.free_tier_limits["daily_requests"]
        
        # 일일 요청 한도 체크
        if self.api_usage["daily_count"] >= self.free_tier_limits["daily_requests"]:
            logger.warning("[LLM] Daily API request limit reached, cannot make more requests today")
            return False
            
        # 분당 요청 한도 체크
        minute_ago = now - timedelta(minutes=1)
        self.api_usage["minute_requests"] = [t for t in self.api_usage["minute_requests"] if t > minute_ago]
        
        if len(self.api_usage["minute_requests"]) >= self.free_tier_limits["per_min"]:
            logger.warning(f"[LLM] Rate limit approaching ({len(self.api_usage['minute_requests'])}/{self.free_tier_limits['per_min']} per minute)")
            return False
            
        return True
    
    def _update_api_usage(self):
        """API 사용 통계를 업데이트합니다."""
        now = datetime.now()
        self.api_usage["daily_count"] += 1
        self.api_usage["last_request_time"] = now
        self.api_usage["minute_requests"].append(now)
        
        with self.stats_lock:
            self.stats["api_requests"] = self.api_usage["daily_count"]
            self.stats["api_requests_remaining"] = max(0, self.free_tier_limits["daily_requests"] - self.api_usage["daily_count"])
    
    def start_continuous_libfuzzer(self):
        """
        커버리지가 누적될 수 있도록 LibFuzzer를 지속적으로 실행합니다.
        반환값: 성공 여부 (True/False)
        """
        with self.libfuzzer_process_lock:
            if self.libfuzzer_process is not None:
                logger.warning("[LibFuzzer] Process already running, terminating it first")
                self.stop_libfuzzer()

            logger.info("[LibFuzzer] Starting continuous fuzzing process")

            options = [
                f"-artifact_prefix={self.crashes_dir}{os.sep}",
                "-print_final_stats=1",
                "-print_pcs=1",          # 커버리지 추적을 위해 PC 출력
                "-print_corpus_stats=1", # 코퍼스 상태 출력
                "-print_new_pcs=1",      # 새로운 PC 출력 (커버리지 정보 수집용)
                "-timeout=10",           # 시간 초과 설정 (10초)
                "-rss_limit_mb=2048"     # 메모리 제한 (2GB)
            ]

            # 시간 제한 제거 (지속적 실행을 위해)
            # max_total_time 옵션은 추가하지 않음

            for k, v in self.libfuzzer_options.items():
                if k != "max_total_time":  # 시간 제한 옵션은 건너뜀
                    options.append(f"-{k}={v}")

            cmd = [self.target_path] + options + [self.corpus_dir]
            logger.debug(f"[LibFuzzer] Command: {' '.join(cmd)}")

            try:
                # 프로세스를 별도의 파이프로 연결하여 출력을 모니터링
                self.libfuzzer_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    bufsize=1  # 라인 버퍼링 활성화
                )
                
                # 출력을 비차단 방식으로 처리하는 스레드 시작
                self.stdout_thread = threading.Thread(
                    target=self._monitor_libfuzzer_output,
                    args=(self.libfuzzer_process.stdout,),
                    daemon=True
                )
                self.stderr_thread = threading.Thread(
                    target=self._monitor_libfuzzer_output,
                    args=(self.libfuzzer_process.stderr,),
                    daemon=True
                )

                self.stdout_thread.start()
                self.stderr_thread.start()

                with self.stats_lock:
                    self.stats["libfuzzer_runs"] += 1
                    # 마지막 통계 업데이트 시간 초기화
                    self.stats["last_stat_update"] = time.time()

                logger.info(f"[LibFuzzer] Continuous process started with PID: {self.libfuzzer_process.pid}")
                return True
                
            except Exception as e:
                logger.error(f"[LibFuzzer] Failed to start process: {e}")
                return False

    def _monitor_libfuzzer_output(self, pipe):
        """
        LibFuzzer 프로세스의 출력을 모니터링하고 통계를 업데이트합니다.
        다양한 출력 형식을 더 잘 처리하도록 개선됨
        """
        try:
            for line in iter(pipe.readline, ''):
                if not line:
                    break

                # 모든 라인 디버그 출력 (문제 진단용)
                logger.debug(f"[LibFuzzer-Raw] {line.strip()}")

                # 프로세스 모니터링을 위한 마지막 업데이트 시간 갱신
                with self.stats_lock:
                    self.stats["last_stat_update"] = time.time()

                # 크래시 발견 시 통계 업데이트
                if "stat::found_crash" in line or "stat::found_crash:" in line:
                    try:
                        val = int(line.split(":")[-1].strip())
                        with self.stats_lock:
                            self.stats["crashes_found"] += val
                            logger.info(f"[LibFuzzer] New crash found! Total: {self.stats['crashes_found']}")
                    except ValueError:
                        pass

                # NEW 라인에서 직접 커버리지 파싱 (이 형식이 로그에 나타남)
                elif "NEW" in line and "cov:" in line:
                    try:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part == "cov:":
                                if i + 1 < len(parts):
                                    val = int(parts[i + 1])
                                    logger.debug(f"[LibFuzzer] 'NEW' 라인에서 커버리지 {val} 파싱됨")
                                    with self.stats_lock:
                                        old_coverage = self.stats.get("coverage", 0)
                                        self.stats["coverage"] = val
                                        if val > old_coverage:
                                            self.last_coverage = val
                                            self.last_coverage_change_time = time.time()
                                            logger.info(f"[LibFuzzer] Coverage increased to {val} paths")
                                    break
                    except (ValueError, IndexError) as e:
                        logger.warning(f"[LibFuzzer] NEW 라인에서 커버리지 파싱 실패: {e}, 라인: {line.strip()}")

                # 실행 수 업데이트 - 다양한 형식 지원
                elif "stat::number_of_executed_units" in line or "stat::executions:" in line or "exec/s:" in line:
                    try:
                        # 기본값을 None으로 설정
                        val = None
                        
                        # 다양한 형식 처리
                        if "stat::number_of_executed_units" in line:
                            val = int(line.split(":")[-1].strip())
                        elif "stat::executions:" in line:
                            val = int(line.split(":")[-1].strip())
                        elif "exec/s:" in line:
                            # 'exec/s:50 rss:' 같은 형식 처리
                            parts = line.split()
                            for i, part in enumerate(parts):
                                if part.startswith("exec/s:"):
                                    # 다음 부분이 실행 총 수를 포함할 수 있음
                                    if i+2 < len(parts) and parts[i+1] == "total:":
                                        val = int(parts[i+2].strip())
                                        break
                                    else:
                                        # 직접적인 값을 찾을 수 없음 - 증분
                                        with self.stats_lock:
                                            self.stats["total_execs"] = self.stats.get("total_execs", 0) + 50  # 대략적인 증가
                                        # val은 설정하지 않고 계속 진행
                        
                        # val이 성공적으로 설정된 경우에만 처리
                        if val is not None:
                            with self.stats_lock:
                                # 값이 현재보다 작으면 증분으로 간주
                                if val < self.stats.get("total_execs", 0):
                                    logger.warning(f"[LibFuzzer] Execution counter reset detected: {val} < {self.stats.get('total_execs', 0)}")
                                    self.stats["total_execs"] += val
                                else:
                                    self.stats["total_execs"] = val
                    except (ValueError, IndexError) as e:
                        logger.debug(f"[LibFuzzer] Failed to parse execution count: {e} in line: {line.strip()}")

                # 기본 통계 라인에서 정보 추출 (줄 형식: "cov: 123 ft: 456 corp: 78/90b exec: 1234k ...")
                elif " exec:" in line and "cov:" in line:
                    try:
                        # 커버리지 값 추출
                        cov_pattern = re.search(r'cov:\s*(\d+)', line)
                        if cov_pattern:
                            cov_val = int(cov_pattern.group(1))
                            logger.debug(f"[LibFuzzer] 통계 라인에서 커버리지 {cov_val} 파싱됨")
                            with self.stats_lock:
                                old_coverage = self.stats.get("coverage", 0)
                                self.stats["coverage"] = cov_val
                                if cov_val > old_coverage:
                                    self.last_coverage = cov_val
                                    self.last_coverage_change_time = time.time()
                                    logger.info(f"[LibFuzzer] Coverage increased to {cov_val} paths")
                        
                        # 실행 수 추출
                        exec_part = re.search(r'exec:[\s]*(\d+)(?:k|M|G)?', line)
                        if exec_part:
                            exec_str = exec_part.group(1)
                            multiplier = 1
                            if 'k' in line[exec_part.end()-1:exec_part.end()+1]:
                                multiplier = 1000
                            elif 'M' in line[exec_part.end()-1:exec_part.end()+1]:
                                multiplier = 1000000
                            elif 'G' in line[exec_part.end()-1:exec_part.end()+1]:
                                multiplier = 1000000000
                            
                            val = int(exec_str) * multiplier
                            with self.stats_lock:
                                if val > self.stats.get("total_execs", 0):
                                    self.stats["total_execs"] = val
                                    logger.debug(f"[LibFuzzer] Updated execution count to {val} from stat line")
                    except Exception as e:
                        logger.debug(f"[LibFuzzer] Failed to parse exec count from stat line: {e}")

                # 코퍼스 크기 업데이트
                elif "stat::corpus_size" in line:
                    try:
                        val = int(line.split(":")[-1].strip())
                        with self.stats_lock:
                            self.stats["corpus_size"] = val
                    except ValueError:
                        pass

                # 커버리지 관련 정보 (Covered PCs) - 개선된 정규식으로 수정
                elif "cov:" in line:
                    try:
                        # 예: "cov: 123 ft: 456 ..." 또는 "    cov: 123"
                        cov_match = re.search(r'cov:\s*(\d+)', line)
                        if cov_match:
                            val = int(cov_match.group(1))
                            logger.debug(f"[LibFuzzer] 일반 라인에서 커버리지 {val} 파싱됨")
                            with self.stats_lock:
                                old_coverage = self.stats.get("coverage", 0)
                                self.stats["coverage"] = val
                                
                                # 커버리지 변화 감지
                                if val > old_coverage:
                                    self.last_coverage = val
                                    self.last_coverage_change_time = time.time()
                                    logger.info(f"[LibFuzzer] Coverage increased to {val} paths")
                        else:
                            logger.debug(f"[LibFuzzer] 'cov:' 있지만 매치 실패, 라인: {line.strip()}")
                    except (ValueError, IndexError, AttributeError) as e:
                        logger.debug(f"[LibFuzzer] Failed to parse coverage: {e} in line: {line.strip()}")
                        
                # 새로운 PC(커버리지) 발견 정보 수집
                elif "NEW_PC:" in line:
                    try:
                        pc_info = line.strip()
                        with self.stats_lock:
                            # 최근 10개의 새 커버리지 정보만 유지
                            self.stats["recent_new_coverage"].append(pc_info)
                            if len(self.stats["recent_new_coverage"]) > 10:
                                self.stats["recent_new_coverage"].pop(0)
                        
                        # 커버리지 변화 감지
                        self.last_coverage_change_time = time.time()
                        logger.info(f"[LibFuzzer] New path discovered: {pc_info}")
                    except Exception as e:
                        logger.debug(f"[LibFuzzer] Failed to process NEW_PC line: {e}")

                # ASAN(AddressSanitizer) 크래시 감지
                elif "AddressSanitizer:" in line:
                    logger.warning(f"[LibFuzzer] ASAN crash detected: {line.strip()}")
                    with self.stats_lock:
                        self.stats["crashes_found"] = self.stats.get("crashes_found", 0) + 1

                # 실행 속도 정보 추출
                elif "exec/s:" in line:
                    try:
                        # 예: "exec/s: 123 ..."
                        speed_match = re.search(r'exec/s:[\s]*(\d+)', line)
                        if speed_match:
                            val = int(speed_match.group(1))
                            with self.stats_lock:
                                self.stats["exec_speed"] = val
                    except (ValueError, IndexError, AttributeError):
                        pass

                # 기타 중요 메시지 로깅
                elif any(x in line for x in ["CRASH", "ERROR", "WARNING", "NEW_FUNC", "NEW_PC", "ALARM", "TIMEOUT"]):
                    logger.info(f"[LibFuzzer] {line.strip()}")
                else:
                    logger.debug(f"[LibFuzzer] {line.strip()}")
                    
        except Exception as e:
            # 출력 모니터링 중 오류 발생 시 로깅
            logger.error(f"[LibFuzzer] Output monitoring error: {e}")
            import traceback
            logger.error(f"[LibFuzzer] Traceback: {traceback.format_exc()}")

    def stop_libfuzzer(self):
        """
        실행 중인 LibFuzzer 프로세스를 안전하게 종료합니다.
        """
        with self.libfuzzer_process_lock:
            if self.libfuzzer_process is None or self.libfuzzer_process.poll() is not None:
                logger.info("[LibFuzzer] No running process to stop")
                return False

            logger.info(f"[LibFuzzer] Stopping process (PID: {self.libfuzzer_process.pid})")

            try:
                # 프로세스를 안전하게 종료 (SIGTERM)
                self.libfuzzer_process.terminate()

                # 5초 대기 후 여전히 실행 중이면 강제 종료 (SIGKILL)
                for _ in range(5):
                    if self.libfuzzer_process.poll() is not None:
                        break
                    time.sleep(1)

                if self.libfuzzer_process.poll() is None:
                    logger.warning("[LibFuzzer] Process not responding to SIGTERM, sending SIGKILL")
                    self.libfuzzer_process.kill()

                self.libfuzzer_process = None
                return True

            except Exception as e:
                logger.error(f"[LibFuzzer] Error stopping process: {e}")
                return False

    def add_new_testcase(self, filepath):
        """
        실행 중인 LibFuzzer 프로세스에 새 테스트케이스를 추가합니다.
        추가된 테스트케이스는 공유 메모리를 통해 알려집니다.
        """
        logger.info(f"[LibFuzzer] Adding new testcase to corpus: {filepath}")
        self.corpus_queue.put(filepath)

    def process_queue_testcases(self):
        """
        큐에 있는 테스트케이스를 처리합니다.
        """
        items_processed = 0
        while not self.corpus_queue.empty():
            try:
                filepath = self.corpus_queue.get_nowait()
                logger.debug(f"[LibFuzzer] Processing new testcase from queue: {filepath}")
                # LibFuzzer가 자동으로 corpus 디렉토리를 모니터링하기 때문에
                # 여기서는 특별한 처리가 필요하지 않습니다.
                # 큐에서 꺼내기만 하면 됩니다.
                self.corpus_queue.task_done()
                items_processed += 1
            except queue.Empty:
                break

        if items_processed > 0:
            logger.info(f"[LibFuzzer] Processed {items_processed} new testcases")
        return items_processed

    def libfuzzer_worker_thread(self):
        """
        지속적인 LibFuzzer 실행을 관리하는 워커 스레드
        크래시 발생 시 올바르게 복구하도록 개선
        """
        logger.info("[Thread] LibFuzzer worker started")

        last_check_time = time.time()
        consecutive_failures = 0
        max_consecutive_failures = 3
        backoff_time = 1  # 초기 백오프 시간 (초)

        try:
            # 초기 프로세스 시작
            self.start_continuous_libfuzzer()

            while not self.stop_event.is_set():
                # 테스트케이스 큐 처리
                self.process_queue_testcases()

                current_time = time.time()
                
                # 프로세스 상태 확인
                with self.libfuzzer_process_lock:
                    if self.libfuzzer_process is None or self.libfuzzer_process.poll() is not None:
                        # 프로세스가 종료된 경우
                        exit_code = self.libfuzzer_process.poll() if self.libfuzzer_process else None
                        logger.warning(f"[Thread] LibFuzzer process exited unexpectedly (exit code: {exit_code}), restarting...")
                        
                        # 연속 실패 카운터 증가
                        consecutive_failures += 1
                        
                        if consecutive_failures >= max_consecutive_failures:
                            # 연속 실패가 너무 많으면 백오프 시간 증가 (지수적 백오프)
                            wait_time = min(backoff_time * (2 ** (consecutive_failures - max_consecutive_failures)), 60)
                            logger.warning(f"[Thread] Multiple LibFuzzer failures detected, backing off for {wait_time}s before retrying")
                            time.sleep(wait_time)
                        
                        # 통계 리셋 방지를 위해 기존 통계 백업
                        with self.stats_lock:
                            backup_stats = {
                                "total_execs": self.stats.get("total_execs", 0),
                                "coverage": self.stats.get("coverage", 0),
                                "crashes_found": self.stats.get("crashes_found", 0)
                            }
                        
                        # 프로세스 재시작
                        restart_success = self.start_continuous_libfuzzer()
                        
                        if not restart_success:
                            logger.error("[Thread] Failed to restart LibFuzzer, will retry later")
                            time.sleep(5)
                            continue
                            
                        # 정상적으로 시작되었으면 통계 복원 (필요시)
                        with self.stats_lock:
                            # 값이 0이면 백업에서 복원 (재시작 후 초기화됐을 가능성)
                            if self.stats.get("total_execs", 0) == 0:
                                self.stats["total_execs"] = backup_stats["total_execs"]
                            if self.stats.get("coverage", 0) == 0:
                                self.stats["coverage"] = backup_stats["coverage"]
                            if self.stats.get("crashes_found", 0) == 0:
                                self.stats["crashes_found"] = backup_stats["crashes_found"]
                    else:
                        # 프로세스가 정상 실행 중이면 연속 실패 카운터 리셋
                        consecutive_failures = 0
                        backoff_time = 1

                    # 프로세스가 정상인지 주기적으로 확인 (10초마다)
                    if current_time - last_check_time > 10:
                        last_check_time = current_time
                        
                        # 프로세스 활성 확인 (마지막 업데이트 후 30초 이상 지났는지)
                        with self.stats_lock:
                            last_update = self.stats.get("last_stat_update", 0)
                            if current_time - last_update > 30 and self.libfuzzer_process is not None:
                                # 프로세스는 실행 중이지만 통계가 업데이트되지 않음 - 잠재적인 교착 상태
                                logger.warning("[Thread] LibFuzzer seems stuck (no updates in 30s), restarting...")
                                self.stop_libfuzzer()
                                time.sleep(1)
                                self.start_continuous_libfuzzer()
                                
                                # 마지막 업데이트 시간 갱신
                                self.stats["last_stat_update"] = current_time

                # 통계 업데이트 및 출력
                with self.stats_lock:
                    corpus_size = len(os.listdir(self.corpus_dir))
                    crashes_count = len(os.listdir(self.crashes_dir))
                    self.stats["corpus_size"] = corpus_size
                    self.stats["crashes_count"] = crashes_count
                    
                    # 마지막 통계 업데이트 시간 기록
                    self.stats["last_stat_update"] = current_time

                # 주기적인 상태 체크 간격
                time.sleep(1)

        except Exception as e:
            logger.error(f"[Thread] LibFuzzer worker error: {e}")
            import traceback
            logger.error(f"[Thread] Traceback: {traceback.format_exc()}")
        finally:
            logger.info("[Thread] LibFuzzer worker stopping")
            self.stop_libfuzzer()

    def llm_worker_thread(self):
        """
        LLM을 사용하여 새로운 테스트 케이스를 생성하는 워커 스레드
        커버리지가 정체되었을 때와 마지막 호출 후 일정 시간이 지났을 때만 호출
        """
        logger.info("[Thread] LLM worker started")

        while not self.stop_event.is_set():
            try:
                # 현재 커버리지 확인
                current_coverage = 0
                with self.stats_lock:
                    current_coverage = self.stats["coverage"]
                
                # 현재 시간
                current_time = time.time()
                
                # 커버리지 변화 확인
                if current_coverage > self.last_coverage:
                    logger.info(f"[LLM] Coverage increased from {self.last_coverage} to {current_coverage}")
                    self.last_coverage = current_coverage
                    self.last_coverage_change_time = current_time
                
                # 커버리지 정체 시간 계산
                coverage_stagnation_time = current_time - self.last_coverage_change_time
                # 마지막 LLM 호출 이후 시간 계산
                time_since_last_call = current_time - self.last_llm_call_time
                
                # LLM 호출 조건: 
                # 1. 커버리지가 1분 이상 정체되었고
                # 2. 마지막 LLM 호출 후 10분 이상 지났을 때
                if (coverage_stagnation_time >= self.coverage_stagnation_threshold and time_since_last_call >= self.llm_call_interval):
                    
                    logger.info(f"[LLM] Coverage stagnated for {coverage_stagnation_time:.1f}s, "
                            f"last LLM call was {time_since_last_call:.1f}s ago, trying LLM generation")
                    
                    # API 한도 체크
                    if self.free_tier_only and not self._check_api_limits():
                        wait_time = 60  # API 제한에 도달했을 때 대기 시간 (초)
                        logger.info(f"[LLM] API rate limit reached, waiting {wait_time} seconds...")
                        time.sleep(wait_time)
                        continue
                    
                    samples = self.get_interesting_inputs(limit=5)
                    if not samples:
                        logger.info("[LLM] No sample found in the corpus, waiting...")
                        time.sleep(30)
                        continue

                    generated_wat = self.generate_llm_inputs(samples)
                    if not generated_wat:
                        logger.warning("[LLM] Failed to generate new inputs, waiting...")
                        time.sleep(30)
                        continue

                    saved_count = self.save_inputs_to_corpus(generated_wat)

                    with self.stats_lock:
                        self.stats["llm_runs"] += 1

                    logger.info(f"[LLM] LLM input generation completed: {len(generated_wat)} generated, {saved_count} saved")
                    
                    # 마지막 LLM 호출 시간 업데이트
                    self.last_llm_call_time = time.time()
                else:
                    # 조건이 충족되지 않은 경우 상태 로깅
                    if coverage_stagnation_time < self.coverage_stagnation_threshold:
                        logger.debug(f"[LLM] Coverage still changing, waiting... "
                                f"(Last change: {coverage_stagnation_time:.1f}s ago)")
                    elif time_since_last_call < self.coverage_stagnation_threshold:
                        logger.debug(f"[LLM] Last LLM call was too recent ({time_since_last_call:.1f}s ago), "
                                     f"waiting until {(self.llm_call_interval - time_since_last_call):.1f}s more...")
                    
                    # 대기 시간 (로그 과부하 방지)
                    time.sleep(30)

                # 정기적인 상태 출력 (5분마다)
                if int(time_since_last_call) % 300 == 0 and int(time_since_last_call) > 0:
                    logger.info(f"[LLM] Status: coverage={current_coverage}, "
                            f"stagnation time={coverage_stagnation_time:.1f}s, "
                            f"time since last call={time_since_last_call:.1f}s")

            except Exception as e:
                logger.error(f"[LLM] Worker error: {e}")
                time.sleep(30)
                
    def generate_llm_inputs(self, prompt_inputs: list) -> list:
        """
        Gemini API를 사용하여 새로운 WAT 모듈을 생성합니다.
        요청 전에 예상 사용량을 계산하여 사용자에게 확인을 요청합니다.
        """
        logger.info("[LLM] Preparing to generate new WAT modules using Gemini API")

        # WAT 생성을 위한 시스템 프롬프트
        system_prompt = """
# WebAssembly Text Format (WAT) Generator

You are a specialized WebAssembly Text Format (WAT) code generator. Your purpose is to generate valid, compilable WAT modules that are intended for fuzzing WebAssembly implementations. Your output must adhere strictly to the WAT specification and follow the rules outlined below.

## WAT SPECIFICATION RULES

1. **Module Structure:**
   - Each module must start with `(module` and end with `)`.
   - The generated module must be a complete, self-contained entity.

2. **Valid Declarations:**
   - **Functions:** Must follow the pattern  
     `(func $name (export "export_name") (param $p i32) (result i32) ... )`
   - **Globals:**  
     `(global $g (mut i32) (i32.const 0))`
   - **Memory:**  
     e.g., `(memory (export "mem") 1)` or `(memory 1)`
   - **Data:**  
     `(data (i32.const 0) "string")`
   - **Tables:**  
     e.g., `(table (export "tab") 1 10 funcref)`
   - **Types:**  
     e.g., `(type $t (func (param i32) (result i32)))`
   - **Elements:**  
     `(elem (i32.const 0) $func1 $func2)` — ensure that all referenced functions are defined in the module.

3. **Valid Instructions:**
   - **Stack Manipulation:**  
     `local.get`, `local.set`, `local.tee`, `global.get`, `global.set`
   - **Constants:**  
     `i32.const`, `i64.const`, `f32.const`, `f64.const`
   - **Arithmetic:**  
     `i32.add`, `i32.sub`, `i32.mul`, `i32.div_s`, `i32.div_u`, etc.
   - **Comparison:**  
     `i32.eq`, `i32.ne`, `i32.lt_s`, `i32.lt_u`, `i32.gt_s`, `i32.gt_u`, etc.
   - **Memory Operations:**  
     `i32.load`, `i32.store`, etc.
   - **Control Flow:**  
     `block`, `loop`, `if`, `else`, `end`, `br`, `br_if`, `return`, `call`, `call_indirect`

## COMMON ERRORS TO AVOID

1. **Expressions in Type Declarations:**  
   - WRONG: `(param $x (i32.const 0))`  
   - CORRECT: `(param $x i32)`

2. **Local Variable Initialization:**  
   - WRONG: `(local $var i32 (i32.const 42))`  
   - CORRECT:
     ```
     (local $var i32)
     i32.const 42
     local.set $var
     ```

3. **Memory Declaration:**  
   - WRONG: `(memory)`  
   - CORRECT: `(memory 1)` or `(memory (export "mem") 1)`

4. **Function References:**  
   - WRONG: `(call $undefinedFunc)`  
   - CORRECT: Ensure that all functions referenced are defined in the module.

5. **Table and Elements:**  
   - When using `(elem (i32.const 0) $f1 $f2)`, confirm that `$f1` and `$f2` are defined in the module.

6. **Stack-Based Operations:**  
   - WRONG: `i32.eq (i32.const 0)`  
   - CORRECT:
     ```
     i32.const 0
     i32.eq
     ```

7. **Operand Separation:**  
   - Do not use commas to separate operands. All operands must be space-separated in S-expression syntax.

## DIVERSITY REQUIREMENTS

1. Each generated module must include at least 2 different instructions from the following set:  
   `{ i32.load, i32.store, block, loop, if, local.set, i32.eq, i32.lt_s, i32.gt_s }`

2. Use varying memory sizes, export names, and function names between modules.

3. Do not duplicate structures or names from provided examples.

## FORMAT REQUIREMENTS

- **No Comments:** The generated WAT code must not contain any comments.
- **Self-Contained Modules:** Each module must be a complete, independent entity.
- **Parenthesis Matching:** Ensure that every opening parenthesis has a corresponding closing parenthesis.
- **Module Wrappers:** Wrap each generated module with `@MODULE_START` at the beginning and `@MODULE_END` at the end.
- **S-expression Format:** All code must be written in proper S-expression format, with operands separated by spaces and no comma usage.

Your outputs must be compilable with the `wat2wasm` tool without errors.
"""

        # 현재 커버리지 정보 및 에러 피드백 수집
        current_coverage_info = "No coverage data available"
        error_feedback = "No compiler errors to report"
        
        with self.stats_lock:
            # 커버리지 정보 수집
            coverage_amount = self.stats["coverage"]
            recent_coverage = self.stats["recent_new_coverage"][-5:] if self.stats["recent_new_coverage"] else []
            
            if recent_coverage:
                current_coverage_info = f"Current coverage: {coverage_amount} paths. Recent new paths discovered:\n"
                current_coverage_info += "\n".join(recent_coverage)
            else:
                current_coverage_info = f"Current coverage: {coverage_amount} paths. No new paths recently."
        
        # 에러 피드백 수집
        if self.wat_error_history:
            error_feedback = "Previous WAT compilation errors to fix:\n"
            for idx, (wat_fragment, error_msg) in enumerate(self.wat_error_history):
                error_feedback += f"\nError {idx+1}:\n```\n{wat_fragment}\n```\nError message: {error_msg}\n"

        user_prompt = f"""
    We already have some WAT samples for reference, such as:
    {json.dumps(prompt_inputs, indent=2)}

    --- Current Fuzzing Information ---
    {current_coverage_info}

    --- Compiler Error Feedback ---
    {error_feedback}

    --- WAT Generation Request ---
    Now generate at least 3 NEW and DIVERSE valid WAT modules that strictly follow all rules,
    including the DIVERSITY & UNIQUENESS RULES.

    - You must use at least 2 instructions from the set {{ i32.load, i32.store, block, loop, if, local.set, i32.eq, i32.lt, i32.gt }}
    in each module, different from the examples.
    - Use different memory sizes, export names, function names, or table names than in the examples.
    - Do not replicate the same structure or name from the provided examples.
    - If there were previous compiler errors, carefully avoid making the same mistakes.

    Remember:
    - No comments at all.
    - Double-check parentheses matching.
    - All forms must be allowed by wat2wasm.

    Wrap each module with:
    @MODULE_START
    (module
    ...
    )
    @MODULE_END

    No invalid or extra tokens, and no duplication of example names.
    """

        # API 요청에 관한 정보 및 사용자 확인
        if self.free_tier_only:
            remaining_requests = self.free_tier_limits["daily_requests"] - self.api_usage["daily_count"]
            logger.info(f"[LLM] API request count: {self.api_usage['daily_count']}/{self.free_tier_limits['daily_requests']} (remaining: {remaining_requests})")
        
        # 요청 전 사용자 확인 (선택 사항)
        if self.confirm_requests:
            confirm = input(f"Send request to Gemini API? [y/N]: ")
            if not confirm.lower().startswith('y'):
                logger.info("[LLM] Request cancelled by user")
                return []

        # Gemini API 요청
        try:
            headers = {
                "x-goog-api-key": self.gemini_api_key,
                "Content-Type": "application/json"
            }
            
            # Gemini API 형식에 맞게 요청 데이터 구성
            request_data = {
                "contents": [
                    {
                        "role": "user",
                        "parts": [
                            {"text": f"{system_prompt}\n\n{user_prompt}"}
                        ]
                    }
                ],
                "generationConfig": {
                    "temperature": self.llm_temperature,
                    "maxOutputTokens": 8192,  # 출력 토큰 제한
                    "topP": 0.95,
                    "topK": 40
                }
            }
            
            # API 엔드포인트 주소 구성 - 이 부분 수정
            base_url = "https://generativelanguage.googleapis.com/v1beta"
            model_name = self.llm_model  # 모델 이름을 그대로 사용
            url = f"{base_url}/models/{model_name}:generateContent"
            
            # 디버깅을 위한 정보 출력
            logger.debug(f"[LLM] Request URL: {url}")
            logger.debug(f"[LLM] Request headers: {headers}")
            logger.debug(f"[LLM] Request config: {request_data['generationConfig']}")
            
            # 요청 전송
            logger.info(f"[LLM] Sending request to Gemini API (model: {self.llm_model})")
            
            response = requests.post(
                url,
                headers=headers,
                json=request_data,
                timeout=120  # 긴 컨텍스트를 위해 타임아웃 증가
            )
            
            # API 사용량 업데이트
            self._update_api_usage()
            
            if response.status_code != 200:
                logger.error(f"[LLM] HTTP status {response.status_code}, response: {response.text}")
                return []

            # 응답 파싱
            data = response.json()
            logger.debug(f"[LLM] Response data: {json.dumps(data)[:200]}...")
            
            # Gemini API 응답 구조에 맞게 수정
            generated_text = ""
            if "candidates" in data and len(data["candidates"]) > 0:
                candidate = data["candidates"][0]
                if "content" in candidate and "parts" in candidate["content"]:
                    for part in candidate["content"]["parts"]:
                        if "text" in part:
                            generated_text += part["text"]
            
            if not generated_text.strip():
                logger.error("[LLM] Empty response from Gemini API")
                return []

            # 디버깅: LLM이 생성한 원시 텍스트 출력
            logger.debug(f"[LLM Debug] Raw generated text:\n{generated_text[:500]}...")

            # 모듈 추출
            pattern = r'@MODULE_START\s*(.*?)\s*@MODULE_END'
            matches = re.findall(pattern, generated_text, flags=re.DOTALL)
            if not matches:
                # fallback
                logger.debug("[LLM] No @MODULE_START/@MODULE_END markers found, trying to extract modules directly")
                module_pattern = r'(\(module.*?\))'
                matches = re.findall(module_pattern, generated_text, flags=re.DOTALL)

            # 추출된 모듈 수 로깅
            logger.info(f"[LLM] Extracted {len(matches)} WAT modules from response")

            # 필터링
            invalid_tokens = [".text", ".globl", " db ", "`", "define", "lambda", "=>", ":[", ": ["]
            valid_results = []
            for mod_text in matches:
                # 명시적인 \n 문자열을 실제 줄바꿈으로 변환
                mod_text = mod_text.replace("\\n", "\n")
                
                lower_text = mod_text.lower()
                if any(tok in lower_text for tok in invalid_tokens):
                    logger.warning("[LLM] Discarding invalid code with forbidden tokens.")
                    continue
                # (module으로 시작
                if not mod_text.strip().startswith("(module"):
                    logger.warning("[LLM] Discarding text that doesn't start with (module.")
                    continue

                valid_results.append(mod_text.strip())

            logger.info(f"[LLM] {len(valid_results)} valid WAT modules after filtering")
            return valid_results

        except Exception as e:
            logger.error(f"[LLM] Request error: {e}")
            # 스택 트레이스 출력
            import traceback
            logger.debug(f"[LLM] Error trace: {traceback.format_exc()}")
            return []
        
    def save_inputs_to_corpus(self, wat_modules: list) -> int:
        """
        LLM이 생성한 WAT 모듈을 코퍼스 디렉토리에 저장합니다.
        wat2wasm가 사용 가능한 경우, 컴파일하여 .wasm으로 변환합니다.
        컴파일이 성공하고 중복이 아닌 경우에만 유지합니다.
        
        컴파일 오류가 발생하면 해당 오류를 저장하고 나중에 LLM에게 피드백합니다.
        """
        saved = 0
        wat2wasm_available = self._check_wat2wasm()

        # 기존 corpus 파일의 해시 목록 수집 (중복 방지용)
        existing_hashes = set()
        for fname in os.listdir(self.corpus_dir):
            path = os.path.join(self.corpus_dir, fname)
            try:
                with open(path, "rb") as f:
                    data = f.read()
                existing_hashes.add(hashlib.sha256(data).hexdigest())
            except Exception as e:
                logger.warning(f"[Corpus] Failed to hash existing file: {path}, error: {e}")

        for idx, wat_text in enumerate(wat_modules):
            # 전체 WAT 텍스트 로깅 (이전에는 일부만 표시)
            logger.info(f"[LLM] WAT Module #{idx+1}:\n{wat_text}")
            
            wat_hash = hashlib.sha256(wat_text.encode('utf-8')).hexdigest()
            if wat_hash in existing_hashes:
                logger.debug("[LLM] Skipping duplicate WAT input (hash match with corpus).")
                continue

            timestamp = int(time.time() * 1000)
            base_name = f"llm_generated_{timestamp}_{idx}"
            wat_file = f"{os.path.join(self.corpus_dir, base_name)}.wat"

            with open(wat_file, "w") as f:
                f.write(wat_text)

            if wat2wasm_available:
                try:
                    wasm_file = os.path.join(self.corpus_dir, base_name)
                    cmd = ["wat2wasm", wat_file, "-o", wasm_file, "--no-check"]
                    proc = subprocess.run(cmd, capture_output=True, timeout=5)
                    
                    if proc.returncode == 0:
                        # 컴파일 성공
                        logger.info(f"[LLM] Successfully compiled WAT to WASM: {base_name}")
                        # WAT 파일 삭제하지 않고 보존
                        # os.remove(wat_file)  # 이 줄 제거
                        self.add_new_testcase(wasm_file)
                        saved += 1
                        
                        # 새롭게 저장된 바이너리 파일도 해시에 추가
                        with open(wasm_file, "rb") as f:
                            new_hash = hashlib.sha256(f.read()).hexdigest()
                            existing_hashes.add(new_hash)
                        
                        # 성공 통계 업데이트
                        with self.stats_lock:
                            self.stats["wat_compile_success"] = self.stats.get("wat_compile_success", 0) + 1
                    else:
                        # 컴파일 실패 - 에러 정보 저장
                        error_output = proc.stderr.decode('utf-8', 'replace')
                        logger.warning(f"[LLM] wat2wasm failed => discarding. stderr:\n{error_output}")
                        
                        # 에러 피드백 저장 (최대 몇 개만)
                        error_preview = self._extract_error_preview(wat_text, error_output)
                        self._add_error_feedback(error_preview, error_output)
                        
                        # 실패 통계 업데이트
                        with self.stats_lock:
                            self.stats["wat_compile_errors"] = self.stats.get("wat_compile_errors", 0) + 1
                                
                        # 에러 피드백 관련 추가 디버깅을 위해 WAT 파일 임시 보존 (옵션)
                        error_dir = os.path.join(os.path.dirname(self.corpus_dir), "wat_errors")
                        os.makedirs(error_dir, exist_ok=True)
                        error_file = os.path.join(error_dir, f"error_{timestamp}_{idx}.wat")
                        try:
                            # 오류 파일과 메시지를 함께 저장
                            with open(error_file, "w") as f:
                                f.write(f"// ERROR: {error_output.strip()}\n\n")
                                f.write(wat_text)
                            logger.debug(f"[LLM] Saved WAT with error to: {error_file}")
                        except Exception as e:
                            logger.debug(f"[LLM] Failed to save error WAT: {e}")
                        
                except Exception as e:
                    logger.error(f"[LLM] wat2wasm conversion error: {e}")
            else:
                logger.warning("[LLM] wat2wasm not installed => keeping .wat file as is")
                # WAT 파일을 유지

        return saved
        
    def _extract_error_preview(self, wat_text: str, error_output: str) -> str:
        """
        오류가 발생한 WAT 코드에서 관련 부분을 추출합니다.
        wat2wasm 오류 메시지에서 라인 번호 정보를 활용합니다.
        """
        # 라인 번호 추출 시도
        line_match = re.search(r'(\d+):(\d+):', error_output)
        if line_match:
            try:
                line_num = int(line_match.group(1))
                # 에러 주변 5줄 추출 (앞뒤 2줄)
                wat_lines = wat_text.split('\n')
                start = max(0, line_num - 3)
                end = min(len(wat_lines), line_num + 2)
                
                preview_lines = wat_lines[start:end]
                return '\n'.join(preview_lines)
            except (ValueError, IndexError):
                pass
        
        # 라인 번호 추출 실패 시 전체 텍스트의 일부만 반환
        # 너무 길면 LLM에 부담이 될 수 있으므로
        if len(wat_text) > 500:
            return wat_text[:500] + "..."
        return wat_text
    
    def _add_error_feedback(self, code_preview: str, error_msg: str):
        """
        컴파일 에러 정보를 저장합니다. 이 정보는 나중에 LLM 요청 시 피드백으로 제공됩니다.
        """
        # 에러 메시지에서 중요 부분만 추출
        condensed_error = error_msg.strip().split('\n')[0] if error_msg else "Unknown error"
        
        # 히스토리에 추가
        self.wat_error_history.append((code_preview, condensed_error))
        
        # 최대 개수 유지
        if len(self.wat_error_history) > self.max_error_history:
            self.wat_error_history.pop(0)
        
        logger.info(f"[LLM] Added WAT compilation error to feedback history: {condensed_error}")

    def _check_wat2wasm(self) -> bool:
        """wat2wasm 도구의 가용성을 확인합니다."""
        try:
            proc = subprocess.run(["wat2wasm", "--version"], capture_output=True, timeout=2)
            return (proc.returncode == 0)
        except FileNotFoundError:
            return False
        except Exception:
            return False
        
    def get_interesting_inputs(self, limit: int = 5) -> list:
        """
        LLM에 컨텍스트로 제공할 기존 코퍼스에서 몇 가지 샘플 입력을 가져옵니다.
        더 다양한 샘플을 제공하기 위해 전략적으로 선택합니다:
        1. 최근 생성된 파일 (시간순)
        2. 커버리지를 늘린 파일 (가능한 경우)
        3. 무작위 선택된 파일
        """
        paths = [os.path.join(self.corpus_dir, f) for f in os.listdir(self.corpus_dir)]
        if not paths:
            return []

        # 1. 가장 최근 수정된 파일들 (최신 파일은 흥미로울 가능성이 높음)
        paths = sorted(paths, key=os.path.getmtime, reverse=True)[:max(1, limit // 2)]
        remaining = limit - len(paths)

        # 2. WAT 파일이 있으면 일부 포함 (LLM 출력과 더 유사한 형식)
        wat_files = [f for f in os.listdir(self.corpus_dir) if f.endswith('.wat')]
        if wat_files and remaining > 0:
            wat_paths = [os.path.join(self.corpus_dir, f) for f in wat_files]
            sample_size = min(remaining // 2, len(wat_paths))
            if sample_size > 0:
                chosen_wat = random.sample(wat_paths, sample_size)
                paths += chosen_wat
                remaining -= len(chosen_wat)

        # 3. 남은 자리는 무작위 선택으로 채움
        all_files = [os.path.join(self.corpus_dir, f) for f in os.listdir(self.corpus_dir)]
        extra_candidates = [p for p in all_files if p not in paths]
        if remaining > 0 and extra_candidates:
            chosen = random.sample(extra_candidates, min(remaining, len(extra_candidates)))
            paths += chosen

        logger.info(f"[LLM] Selected {len(paths)} diverse samples from corpus")
        
        results = []
        for p in paths:
            try:
                with open(p, "rb") as f:
                    data = f.read()
                wat_text = self.binary_to_wat(data)
                results.append(wat_text)
            except Exception as e:
                logger.error(f"[LLM] Error reading sample: {p}, {e}")
        return results

    def binary_to_wat(self, binary_data: bytes) -> str:
        """
        주어진 바이너리 데이터를 간단한 WAT 문자열로 변환합니다.
        WASM인 경우 외부 도구(wasm2wat)가 있으면 사용하고,
        없으면 최소한의 (module ...)을 생성하거나 i32.const 세그먼트로 취급합니다.
        """
        # 먼저 wasm2wat 도구로 변환 시도
        if binary_data[0:4] == b"\0asm" and len(binary_data) >= 8:
            try:
                # wasm2wat 도구 사용 시도 (설치되어 있는 경우)
                with tempfile.NamedTemporaryFile(suffix='.wasm', delete=False) as temp_wasm:
                    temp_wasm.write(binary_data)
                    temp_wasm_path = temp_wasm.name
                
                try:
                    proc = subprocess.run(
                        ["wasm2wat", temp_wasm_path], 
                        capture_output=True, 
                        timeout=3
                    )
                    os.unlink(temp_wasm_path)
                    
                    if proc.returncode == 0:
                        wat_content = proc.stdout.decode('utf-8', 'replace')
                        if wat_content.strip().startswith('(module') and wat_content.strip().endswith(')'):
                            return wat_content
                except (subprocess.SubprocessError, FileNotFoundError):
                    # wasm2wat가 없거나 실패하면 기본 변환으로 대체
                    pass
                except Exception as e:
                    logger.debug(f"[LLM] wasm2wat failed: {e}")
                
                # 임시 파일 정리
                if os.path.exists(temp_wasm_path):
                    try:
                        os.unlink(temp_wasm_path)
                    except:
                        pass
            except Exception as e:
                logger.debug(f"[LLM] Error in wasm2wat conversion: {e}")
        
        # 기본 변환 로직
        wat_lines = ["(module"]
        if len(binary_data) < 8 or binary_data[0:4] != b"\0asm":
            wat_lines.append("  (func (export \"fuzz_target\") (result i32)")
            for i in range(0, min(len(binary_data), 100), 4):  # 너무 길지 않게 제한
                chunk = binary_data[i:i+4]
                if len(chunk) < 4:
                    chunk += b"\0"*(4-len(chunk))
                val = struct.unpack("<I", chunk)[0]
                wat_lines.append(f"    i32.const {val}")
                if i < len(binary_data)-4:
                    wat_lines.append("    drop")
            wat_lines.append("  )")
        else:
            # WASM 헤더가 있지만 wasm2wat 변환에 실패한 경우
            # 간단한 더미 모듈 생성
            wat_lines.append("  (memory (export \"memory\") 1)")
            wat_lines.append("  (func (export \"main\") (result i32)")
            wat_lines.append("    i32.const 42")
            wat_lines.append("  )")
        wat_lines.append(")")
        return "\n".join(wat_lines)
    
    def llm_test_mode(self):
        """LLM 기능만 테스트합니다."""
        logger.info("[TEST] Testing Gemini API connection...")
        connection_ok = self._test_gemini_connection()
        
        if not connection_ok:
            logger.error("[TEST] Gemini API connection test failed!")
            return False

        logger.info("[TEST] API connection test successful!")
        
        # 샘플 데이터 수집
        logger.info("[TEST] Collecting sample inputs from corpus...")
        samples = self.get_interesting_inputs(limit=3)
        
        if not samples:
            logger.warning("[TEST] No samples found in corpus. Using dummy sample.")
            samples = ["""(module
    (memory (export "memory") 1)
    (func (export "main") (result i32)
        i32.const 42
    )
    )"""]
        
        # 샘플 출력
        for i, sample in enumerate(samples):
            logger.info(f"[TEST] Sample {i+1}:\n{sample}")
        
        # WAT 생성 테스트
        logger.info("[TEST] Testing WAT generation with Gemini API...")
        generated_wat = self.generate_llm_inputs(samples)
        
        if not generated_wat:
            logger.error("[TEST] Failed to generate WAT modules!")
            return False
        
        logger.info(f"[TEST] Successfully generated {len(generated_wat)} WAT modules")
        
        # 결과 저장
        logger.info("[TEST] Testing saving generated WATs to corpus...")
        saved_count = self.save_inputs_to_corpus(generated_wat)
        
        logger.info(f"[TEST] Test completed: {len(generated_wat)} WAT modules generated, {saved_count} saved to corpus")
        
        # 생성된 WAT 파일 경로 출력
        wat_files = [f for f in os.listdir(self.corpus_dir) if f.endswith('.wat')]
        if wat_files:
            logger.info("[TEST] Generated WAT files:")
            for wat_file in wat_files:
                logger.info(f" - {os.path.join(self.corpus_dir, wat_file)}")
        
        return True
        
    def run(self, total_time: int = 3600) -> dict:
        """
        지속적인 커버리지 축적을 위해 수정된 실행 메서드
        에러 피드백 및 커버리지 정보 공유 기능 포함
        """
        logger.info(f"[RUN] Starting enhanced hybrid fuzzing (total time: {total_time}s)")
        logger.info(f"[RUN] Error feedback: {'Enabled' if self.max_error_history > 0 else 'Disabled'}")
        logger.info(f"[RUN] Free tier API limits: {'Enabled' if self.free_tier_only else 'Disabled'}")

        start_time = time.time()
        threads = []

        # LibFuzzer 워커 스레드 (1개로 통합)
        libfuzzer_thread = threading.Thread(
            target=self.libfuzzer_worker_thread,
            name="LibFuzzer-Main-Worker",
            daemon=True
        )
        threads.append(libfuzzer_thread)
        libfuzzer_thread.start()
        logger.info("[RUN] LibFuzzer main worker started")

        # LLM 워커 스레드
        if self.llm_cycles > 0:
            for i in range(self.llm_cycles):
                th = threading.Thread(
                    target=self.llm_worker_thread,
                    name=f"LLM-Worker-{i+1}",
                    daemon=True
                )
                threads.append(th)
                th.start()
                logger.info(f"[RUN] LLM worker #{i+1} started")

        try:
            end_time = start_time + total_time
            last_stats_time = 0
            last_feedback_time = 0  # 에러 피드백 요약을 위한 타임스탬프
            last_api_stats_time = 0 # API 사용량 통계를 위한 타임스탬프

            while True:
                now = time.time()
                if now >= end_time:
                    break

                elapsed = now - start_time
                remaining = end_time - now

                # 10초마다 상태 출력
                if int(elapsed) % 10 == 0 and int(elapsed) != last_stats_time:
                    last_stats_time = int(elapsed)
                    with self.stats_lock:
                        # 현재 상태 업데이트 (스레드에서 이미 업데이트하고 있지만 보험으로)
                        corpus_size = len(os.listdir(self.corpus_dir))
                        crashes_count = len(os.listdir(self.crashes_dir))

                        logger.info(f"[RUN] {elapsed:.1f}s elapsed (remaining {remaining:.1f}s), "
                                    f"Executions: {self.stats['total_execs']}, "
                                    f"Coverage: {self.stats['coverage']}, "
                                    f"Crashes: {self.stats['crashes_found']}, "
                                    f"Corpus size: {corpus_size}")
                
                # 30초마다 API 사용량 통계 출력
                if self.free_tier_only and int(elapsed) % 30 == 0 and int(elapsed) != last_api_stats_time:
                    last_api_stats_time = int(elapsed)
                    with self.stats_lock:
                        api_requests = self.stats.get("api_requests", 0)
                        api_remaining = self.stats.get("api_requests_remaining", 0)
                        logger.info(f"[API] Usage: {api_requests}/{self.free_tier_limits['daily_requests']} requests "
                                    f"(remaining: {api_remaining})")
                        
                        # 리셋 시간 표시
                        next_reset = self.free_tier_limits["reset_time"]
                        now_time = datetime.now()
                        if next_reset > now_time:
                            hours_to_reset = (next_reset - now_time).total_seconds() / 3600
                            logger.info(f"[API] Next limit reset in {hours_to_reset:.1f} hours")
                
                # 60초마다 WAT 컴파일 에러 피드백 요약 출력
                if self.max_error_history > 0 and int(elapsed) % 60 == 0 and int(elapsed) != last_feedback_time:
                    last_feedback_time = int(elapsed)
                    error_count = len(self.wat_error_history)
                    if error_count > 0:
                        with self.stats_lock:
                            success = self.stats.get("wat_compile_success", 0)
                            errors = self.stats.get("wat_compile_errors", 0)
                            total = success + errors
                            if total > 0:
                                success_rate = (success / total) * 100
                                logger.info(f"[LLM] WAT compilation status: {success_rate:.1f}% success rate ({success}/{total})")
                                logger.info(f"[LLM] Active error feedback items: {error_count}")

                time.sleep(1)

        except KeyboardInterrupt:
            logger.info("[RUN] Stopped by user (Ctrl+C)")

        finally:
            logger.info("[RUN] Sending stop signal to all threads...")
            self.stop_event.set()

            # 안전하게 LibFuzzer 중지
            self.stop_libfuzzer()

            # 스레드 종료 대기
            for th in threads:
                logger.info(f"[RUN] Waiting for thread {th.name} to exit...")
                th.join(timeout=5)
                if th.is_alive():
                    logger.warning(f"[RUN] Thread {th.name} did not exit in time.")

            # 최종 통계 수집
            with self.stats_lock:
                self.stats["total_time"] = time.time() - start_time
                self.stats["corpus_size"] = len(os.listdir(self.corpus_dir))
                self.stats["crashes_count"] = len(os.listdir(self.crashes_dir))

            logger.info("=== Fuzzing finished ===")
            logger.info(f"Total executions : {self.stats['total_execs']}")
            logger.info(f"Total coverage   : {self.stats['coverage']} PCs")
            logger.info(f"Total crashes    : {self.stats['crashes_found']}")
            logger.info(f"Corpus size      : {self.stats['corpus_size']}")
            logger.info(f"Total run time   : {self.stats['total_time']:.2f}s")
            
            # WAT 컴파일 관련 통계 추가
            if "wat_compile_success" in self.stats or "wat_compile_errors" in self.stats:
                success = self.stats.get("wat_compile_success", 0)
                errors = self.stats.get("wat_compile_errors", 0)
                total = success + errors
                
                if total > 0:
                    success_rate = (success / total) * 100
                    logger.info(f"WAT compilation   : {success_rate:.2f}% success rate ({success}/{total})")
                    
            # API 사용량 통계 출력
            logger.info(f"API requests     : {self.stats.get('api_requests', 0)}/{self.free_tier_limits['daily_requests']}")

            return self.stats


def main():
    parser = argparse.ArgumentParser(description='LibFuzzer+Gemini LLM Hybrid Fuzzer with continuous fuzzing and error feedback')
    parser.add_argument('--target', '-t', required=True, help='Path to the Walrus fuzzing target')
    parser.add_argument('--corpus', '-c', required=True, help='Corpus directory')
    parser.add_argument('--time', type=int, default=3600, help='Total fuzzing time (seconds)')
    parser.add_argument('--libfuzzer-cycles', type=int, default=1, help='DEPRECATED: Now use single LibFuzzer process for better coverage accumulation')
    parser.add_argument('--llm-cycles', type=int, default=1, help='Number of parallel LLM workers')
    parser.add_argument('--llm-model', default='gemini-1.5-pro', help='Gemini model to use (gemini-1.5-pro, gemini-1.0-pro, etc.)')
    parser.add_argument('--gemini-api-key', help='Gemini API key (or set GEMINI_API_KEY environment variable)')
    parser.add_argument('--libfuzzer-options', help='LibFuzzer options (JSON)')
    parser.add_argument('--max-error-history', type=int, default=3, help='Maximum number of error feedback items to store for LLM')
    parser.add_argument('--feedback-enabled', action='store_true', default=True, help='Enable error feedback to LLM')
    parser.add_argument('--confirm-requests', action='store_true', default=True, help='Confirm API requests before sending')
    parser.add_argument('--free-tier-only', action='store_true', default=True, help='Respect free tier API limits')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable debug output')
    parser.add_argument('--llm-test', action='store_true', help='Only test LLM functionality without starting LibFuzzer')

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # Gemini API 키 설정 확인
    if args.gemini_api_key:
        os.environ["GEMINI_API_KEY"] = args.gemini_api_key
    elif "GEMINI_API_KEY" not in os.environ:
        logger.error("[INIT] Gemini API key not provided. Use --gemini-api-key or set GEMINI_API_KEY environment variable.")
        sys.exit(1)

    # 경고: libfuzzer-cycles 변수가 1보다 큰 경우
    if args.libfuzzer_cycles > 1:
        logger.warning("[INIT] --libfuzzer-cycles > 1 is deprecated in continuous mode. Using 1 for better coverage.")
        args.libfuzzer_cycles = 1

    # 최소한의 LibFuzzer 옵션 설정 (독립적인 프로세스 형태로 변경되어 일부 옵션은 무시됨)
    libfuzzer_options = {}
    if args.libfuzzer_options:
        try:
            libfuzzer_options = json.loads(args.libfuzzer_options)
            # 필요한 경우 max_total_time 옵션 제거 (지속적인 실행을 위해)
            if "max_total_time" in libfuzzer_options:
                logger.warning("[INIT] Removing 'max_total_time' option for continuous fuzzing")
                del libfuzzer_options["max_total_time"]
        except json.JSONDecodeError:
            logger.error("Error parsing LibFuzzer options - must be valid JSON.")
            sys.exit(1)

    # wat2wasm 도구 확인
    try:
        subprocess.run(["wat2wasm", "--version"], capture_output=True)
        logger.info("[INIT] Found wat2wasm tool")
    except FileNotFoundError:
        logger.warning("[INIT] wat2wasm not installed - WAT text will be stored as-is")
        
    # wasm2wat 도구 확인 (추가 기능)
    try:
        subprocess.run(["wasm2wat", "--version"], capture_output=True)
        logger.info("[INIT] Found wasm2wat tool for better binary->WAT conversion")
    except FileNotFoundError:
        logger.info("[INIT] wasm2wat not installed - using basic WAT conversion")

    # 시그널 핸들러 설정 (안전한 종료)
    def signal_handler(sig, frame):
        logger.info(f"[MAIN] Received signal {sig}, initiating graceful shutdown")
        if fuzzer and not fuzzer.stop_event.is_set():
            fuzzer.stop_event.set()
            if not args.llm_test:
                fuzzer.stop_libfuzzer()  # 실행 중인 LibFuzzer 프로세스 안전하게 종료
        sys.exit(0)

    # SIGINT 및 SIGTERM에 대한 핸들러 등록
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    fuzzer = HybridFuzzer(
        target_path=args.target,
        corpus_dir=args.corpus,
        libfuzzer_options=libfuzzer_options,
        llm_model=args.llm_model,
        libfuzzer_cycles=1,  # 항상 1개 (연속 실행 모드로 변경됨)
        llm_cycles=args.llm_cycles,
        gemini_api_key=args.gemini_api_key,
        confirm_requests=args.confirm_requests,
        free_tier_only=args.free_tier_only,
    )
    
    # 에러 피드백 설정 적용
    if args.feedback_enabled:
        fuzzer.max_error_history = args.max_error_history
    else:
        # 피드백 비활성화
        fuzzer.max_error_history = 0
        fuzzer.wat_error_history = []

    if args.llm_test:
        # LLM 기능만 테스트
        logger.info("[MAIN] Running in LLM test mode (LibFuzzer disabled)")
        
        # llm_test_mode 메서드 호출
        test_success = fuzzer.llm_test_mode()
        
        if test_success:
            logger.info("[MAIN] LLM test completed successfully")
        else:
            logger.error("[MAIN] LLM test failed")
        
    else:
        # 일반 하이브리드 퍼징 실행
        logger.info("[MAIN] Starting HybridFuzzer with continuous LibFuzzer execution")
        logger.info(f"[MAIN] Error feedback is {'enabled' if args.feedback_enabled else 'disabled'}")
        logger.info(f"[MAIN] Free tier limits are {'enabled' if args.free_tier_only else 'disabled'}")
        
        stats = fuzzer.run(total_time=args.time)

        # 최종 결과 출력
        print(json.dumps(stats, indent=2))
        
        # 통계 로깅
        logger.info("=== WAT Compilation Statistics ===")
        logger.info(f"Total WAT compilation attempts: {stats.get('wat_compile_success', 0) + stats.get('wat_compile_errors', 0)}")
        logger.info(f"Successful WAT compilations: {stats.get('wat_compile_success', 0)}")
        logger.info(f"Failed WAT compilations: {stats.get('wat_compile_errors', 0)}")
        
        if stats.get('wat_compile_errors', 0) > 0 and stats.get('wat_compile_success', 0) > 0:
            success_rate = (stats['wat_compile_success'] / 
                            (stats['wat_compile_success'] + stats['wat_compile_errors'])) * 100
            logger.info(f"WAT compilation success rate: {success_rate:.2f}%")
        
        # API 사용량 통계
        logger.info("=== API Usage Statistics ===")
        logger.info(f"Total API requests: {stats.get('api_requests', 0)}")
        logger.info(f"Daily API limit: {stats.get('api_free_tier_limit', 0)}")
        logger.info(f"Remaining API requests: {stats.get('api_requests_remaining', 0)}")

if __name__ == "__main__":
    main()
