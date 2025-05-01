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
import shutil
import curses
import psutil
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
        llm_model: str = "gemini-1.5-pro",
        llm_temperature: float = 0.7,
        libfuzzer_cycles: int = 1,
        llm_cycles: int = 1,
        gemini_api_key: str = None,
        confirm_requests: bool = False,
        free_tier_only: bool = True,
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
        self.llm_call_interval = 60  # LLM 호출 간격 (10분 = 600초)

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
            "api_requests_remaining": self.free_tier_limits["daily_requests"],
            # CPU 및 속도 모니터링 관련 추가 항목
            "cpu_percent": 0,
            "cpu_per_core": 0,
            "exec_speed": 0,
            "avg_exec_speed": 0,
            "exec_speed_samples": []
        }

        self.use_dashboard = False
        self.screen = None
        self.log_buffer = []
        self.max_log_lines = 30

    def _update_system_stats(self):
        """
        시스템 통계(CPU 사용량, 메모리 등)를 업데이트합니다.
        """
        try:
            # 현재 프로세스의 CPU 사용량 가져오기
            process = psutil.Process(os.getpid())
            
            # 전체 프로세스 트리의 CPU 사용량 합산
            total_cpu_percent = process.cpu_percent(interval=0.1)
            
            # LibFuzzer 프로세스가 있다면 그 프로세스도 포함
            if self.libfuzzer_process is not None and self._is_process_running(self.libfuzzer_process.pid):
                try:
                    libfuzzer_process = psutil.Process(self.libfuzzer_process.pid)
                    total_cpu_percent += libfuzzer_process.cpu_percent(interval=0.1)
                    
                    # 자식 프로세스들도 포함
                    for child in libfuzzer_process.children(recursive=True):
                        try:
                            total_cpu_percent += child.cpu_percent(interval=0.1)
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # 프로세서 수
            cpu_count = psutil.cpu_count(logical=True)
            
            # CPU 사용률 및 코어당 사용률 계산
            with self.stats_lock:
                self.stats["cpu_percent"] = round(total_cpu_percent, 1)
                self.stats["cpu_per_core"] = round(total_cpu_percent / max(1, cpu_count), 1)
                logger.debug(f"[System] CPU usage: {self.stats['cpu_percent']}% (per core: {self.stats['cpu_per_core']}%)")

        except Exception as e:
            logger.error(f"[System] Failed to update CPU stats: {e}")
            with self.stats_lock:
                self.stats["cpu_percent"] = 0
                self.stats["cpu_per_core"] = 0


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
            # 기존 프로세스 정리
            if self.libfuzzer_process is not None:
                logger.warning("[LibFuzzer] Process already running, terminating it first")
                try:
                    self.stop_libfuzzer()
                except Exception as e:
                    logger.error(f"[LibFuzzer] Error during process cleanup: {e}")
                
                # 이전 프로세스가 완전히 종료될 때까지 기다림
                time.sleep(2)
                
                # 프로세스 변수 초기화
                self.libfuzzer_process = None

            logger.info("[LibFuzzer] Starting continuous fuzzing process")

            # LibFuzzer 옵션 구성
            options = [
                f"-artifact_prefix={self.crashes_dir}{os.sep}",
                "-print_final_stats=1",
                "-print_pcs=1",          # 커버리지 추적을 위해 PC 출력
                "-print_corpus_stats=1", # 코퍼스 상태 출력
                "-print_new_pcs=1"       #옵션 제거 (에러 발생 시)
                "-timeout=30",           # 시간 초과 설정 (10초)
                "-rss_limit_mb=4096"     # 메모리 제한 (2GB)
            ]

            # 사용자 정의 옵션 추가
            for k, v in self.libfuzzer_options.items():
                if k != "max_total_time":  # 시간 제한 옵션은 건너뜀
                    options.append(f"-{k}={v}")

            cmd = [self.target_path] + options + [self.corpus_dir]
            logger.debug(f"[LibFuzzer] Command: {' '.join(cmd)}")

            try:
                # 명시적으로 환경 변수 복사하여 전달
                env = os.environ.copy()
                
                # 프로세스 생성
                logger.info("[LibFuzzer] Creating new process...")
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    bufsize=1,  # 라인 버퍼링 활성화
                    env=env,
                    preexec_fn=os.setsid  # 새로운 프로세스 그룹 생성 (리눅스 전용)
                )
                
                # 프로세스 시작 확인
                if process.poll() is not None:
                    logger.error(f"[LibFuzzer] Process terminated immediately with code {process.poll()}")
                    return False
                
                logger.info(f"[LibFuzzer] Process created with PID: {process.pid}")
                
                # 출력 모니터링 스레드 시작
                stdout_thread = threading.Thread(
                    target=self._monitor_libfuzzer_output,
                    args=(process.stdout,),
                    daemon=True,
                    name=f"stdout-{process.pid}"
                )
                
                stderr_thread = threading.Thread(
                    target=self._monitor_libfuzzer_output,
                    args=(process.stderr,),
                    daemon=True,
                    name=f"stderr-{process.pid}"
                )
                
                stdout_thread.start()
                stderr_thread.start()
                
                # 프로세스와 스레드 참조 저장
                self.libfuzzer_process = process
                self.stdout_thread = stdout_thread
                self.stderr_thread = stderr_thread
                
                # 통계 업데이트
                with self.stats_lock:
                    self.stats["libfuzzer_runs"] += 1
                    self.stats["last_stat_update"] = time.time()
                    
                # 프로세스가 실제로 실행되고 있는지 확인 (최대 5초 대기)
                start_time = time.time()
                while time.time() - start_time < 5:
                    if process.poll() is not None:
                        # 5초 내에 종료됨
                        logger.error(f"[LibFuzzer] Process terminated during startup with code {process.poll()}")
                        return False
                    
                    # 프로세스가 여전히 실행 중이면 성공으로 간주
                    if self._is_process_running(process.pid):
                        logger.info(f"[LibFuzzer] Continuous process confirmed running with PID: {process.pid}")
                        return True
                    
                    time.sleep(0.5)
                
                # 5초 후에도 실행 중이면 성공
                if self._is_process_running(process.pid):
                    logger.info(f"[LibFuzzer] Continuous process started with PID: {process.pid}")
                    return True
                else:
                    logger.error("[LibFuzzer] Process appears to be running but PID check failed")
                    return False
                    
            except Exception as e:
                logger.error(f"[LibFuzzer] Failed to start process: {e}")
                import traceback
                logger.error(f"[LibFuzzer] Exception traceback: {traceback.format_exc()}")
                return False

    def _is_process_running(self, pid):
        """특정 PID의 프로세스가 실행 중인지 확인합니다."""
        try:
            # 리눅스/맥OS에서 프로세스 존재 여부 확인
            os.kill(pid, 0)
            return True
        except OSError:
            return False
        except Exception as e:
            logger.error(f"[LibFuzzer] Error checking process status: {e}")
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
                line_strip = line.strip()
                logger.debug(f"[LibFuzzer-Raw] {line_strip}")

                # 프로세스 모니터링을 위한 마지막 업데이트 시간 갱신
                with self.stats_lock:
                    self.stats["last_stat_update"] = time.time()

                # 정확한 패턴 찾기: "#123 pulse cov: 1625 ft: 4319 corp: 184/24Kb exec/s: 85 rss: 94Mb"
                pulse_pattern = re.search(r'#\d+\s+pulse\s+cov:\s*(\d+)', line_strip)
                if pulse_pattern:
                    try:
                        # 실행 횟수 추출 - "#123" 부분 파싱
                        exec_num_match = re.search(r'#(\d+)', line_strip)
                        if exec_num_match:
                            try:
                                exec_num = int(exec_num_match.group(1))
                                with self.stats_lock:
                                    # 초기값이 0이거나 현재 값보다 큰 경우에만 업데이트
                                    if self.stats.get("total_execs", 0) == 0 or exec_num > self.stats.get("total_execs", 0):
                                        self.stats["total_execs"] = exec_num
                                        logger.debug(f"[LibFuzzer] Updated execution count to {exec_num} from pulse line")
                            except ValueError:
                                pass
                        
                        # 커버리지 값 추출
                        cov_val = int(pulse_pattern.group(1))
                        logger.debug(f"[LibFuzzer] 펄스 라인에서 커버리지 발견: {cov_val}")
                        with self.stats_lock:
                            old_coverage = self.stats.get("coverage", 0)
                            self.stats["coverage"] = cov_val
                            if cov_val > old_coverage:
                                self.last_coverage = cov_val
                                self.last_coverage_change_time = time.time()
                                logger.info(f"[LibFuzzer] Coverage increased to {cov_val} paths")
                                
                        # 같은 라인에서 exec/s 값도 추출
                        exec_speed_match = re.search(r'exec/s:\s*(\d+)', line_strip)
                        if exec_speed_match:
                            try:
                                speed_val = int(exec_speed_match.group(1))
                                with self.stats_lock:
                                    self.stats["exec_speed"] = speed_val
                                    
                                    # 평균 속도 계산을 위한 샘플 수집
                                    self.stats.setdefault("exec_speed_samples", []).append(speed_val)
                                    # 최근 10개 샘플만 유지
                                    if len(self.stats["exec_speed_samples"]) > 10:
                                        self.stats["exec_speed_samples"].pop(0)
                                        
                                    # 평균 속도 계산
                                    if self.stats["exec_speed_samples"]:
                                        self.stats["avg_exec_speed"] = int(sum(self.stats["exec_speed_samples"]) / 
                                                                len(self.stats["exec_speed_samples"]))
                                        logger.debug(f"[LibFuzzer] Execution speed: {speed_val}/sec (avg: {self.stats['avg_exec_speed']}/sec)")
                            except (ValueError, IndexError, AttributeError):
                                pass
                            
                        # 코퍼스 크기 추출
                        corp_match = re.search(r'corp:\s*(\d+)', line_strip)
                        if corp_match:
                            try:
                                corpus_size = int(corp_match.group(1))
                                with self.stats_lock:
                                    self.stats["corpus_size"] = corpus_size
                            except ValueError:
                                pass
                    except ValueError:
                        pass
                        
                # 크래시 발견 시 통계 업데이트
                elif "stat::found_crash" in line or "stat::found_crash:" in line:
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
                        elif "exec/s:" in line and "pulse" not in line:  # pulse 라인과 구분
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

                # 일반적인 cov: 패턴 처리 (pulse 라인이 아닌 경우)
                elif "cov:" in line and "pulse" not in line:
                    try:
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

                # 실행 속도 정보 추출 (pulse 라인이 아닌 경우)
                elif "exec/s:" in line and "pulse" not in line:
                    try:
                        # 예: "exec/s: 123 ..."
                        speed_match = re.search(r'exec/s:[\s]*(\d+)', line)
                        if speed_match:
                            val = int(speed_match.group(1))
                            with self.stats_lock:
                                self.stats["exec_speed"] = val
                                
                                # 평균 속도 계산을 위한 샘플 수집
                                self.stats.setdefault("exec_speed_samples", []).append(val)
                                # 최근 10개 샘플만 유지
                                if len(self.stats["exec_speed_samples"]) > 10:
                                    self.stats["exec_speed_samples"].pop(0)
                                    
                                # 평균 속도 계산
                                if self.stats["exec_speed_samples"]:
                                    self.stats["avg_exec_speed"] = int(sum(self.stats["exec_speed_samples"]) / 
                                                            len(self.stats["exec_speed_samples"]))
                                    logger.debug(f"[LibFuzzer] Execution speed: {val}/sec (avg: {self.stats['avg_exec_speed']}/sec)")
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
            if self.libfuzzer_process is None:
                logger.info("[LibFuzzer] No running process to stop")
                return False

            if self.libfuzzer_process.poll() is not None:
                logger.info(f"[LibFuzzer] Process already exited with code {self.libfuzzer_process.poll()}")
                self.libfuzzer_process = None
                return True

            logger.info(f"[LibFuzzer] Stopping process group (PID: {self.libfuzzer_process.pid})")

            try:
                pid = self.libfuzzer_process.pid
                
                # 리눅스에서는 프로세스 그룹 전체 종료 시도
                try:
                    os.killpg(os.getpgid(pid), signal.SIGTERM)
                    logger.info(f"[LibFuzzer] Sent SIGTERM to process group of PID {pid}")
                except (OSError, AttributeError) as e:
                    logger.warning(f"[LibFuzzer] Failed to kill process group: {e}, trying direct terminate")
                    # 개별 프로세스 종료로 대체
                    self.libfuzzer_process.terminate()
                    
                # 최대 5초 동안 프로세스 종료 대기
                for i in range(10):
                    if not self._is_process_running(pid):
                        logger.info(f"[LibFuzzer] Process {pid} terminated successfully")
                        break
                        
                    # 0.5초 대기
                    time.sleep(0.5)
                    
                    # 세 번째 시도 후에는 더 적극적으로 종료 시도
                    if i >= 3 and self._is_process_running(pid):
                        logger.warning(f"[LibFuzzer] Process {pid} still running, sending SIGKILL")
                        try:
                            os.killpg(os.getpgid(pid), signal.SIGKILL)
                        except:
                            # 개별 프로세스 강제 종료
                            self.libfuzzer_process.kill()
                
                # 종료 확인
                if self._is_process_running(pid):
                    logger.error(f"[LibFuzzer] Failed to terminate process {pid} after multiple attempts")
                else:
                    logger.info(f"[LibFuzzer] Process {pid} confirmed terminated")
                
                # 자원 정리
                try:
                    if self.libfuzzer_process.stdout:
                        self.libfuzzer_process.stdout.close()
                    if self.libfuzzer_process.stderr:
                        self.libfuzzer_process.stderr.close()
                except Exception as e:
                    logger.debug(f"[LibFuzzer] Error closing process streams: {e}")
                    
                # 프로세스 객체 정리
                self.libfuzzer_process = None
                
                return True

            except Exception as e:
                logger.error(f"[LibFuzzer] Error stopping process: {e}")
                import traceback
                logger.error(f"[LibFuzzer] Error trace: {traceback.format_exc()}")
                
                # 오류가 발생해도 프로세스 객체를 None으로 설정
                self.libfuzzer_process = None
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
        last_system_stats_time = time.time()  # 시스템 통계 업데이트 타이머
        last_stats_print_time = time.time()   # 상태 출력 타이머
        consecutive_failures = 0
        max_consecutive_failures = 3
        backoff_time = 1  # 초기 백오프 시간 (초)

        try:
            # 초기 프로세스 시작
            success = self.start_continuous_libfuzzer()
            if not success:
                logger.error("[Thread] Initial LibFuzzer process failed to start")
                # 처음부터 실패하면 짧은 대기 후 재시도
                time.sleep(5)
                success = self.start_continuous_libfuzzer()
                if not success:
                    logger.critical("[Thread] Failed to start LibFuzzer twice, worker thread exiting")
                    return

            while not self.stop_event.is_set():
                # 테스트케이스 큐 처리
                self.process_queue_testcases()

                current_time = time.time()
                
                # 5초마다 시스템 통계(CPU 등) 업데이트
                if current_time - last_system_stats_time > 5:
                    self._update_system_stats()
                    last_system_stats_time = current_time
                
                # 프로세스 상태 확인
                process_running = False
                
                with self.libfuzzer_process_lock:
                    # 프로세스 객체가 있고, poll()이 None이면 실행 중
                    if self.libfuzzer_process is not None and self.libfuzzer_process.poll() is None:
                        process_running = True
                        
                        # 더 확실한 확인: PID가 실제로 존재하는지
                        if not self._is_process_running(self.libfuzzer_process.pid):
                            logger.warning(f"[Thread] Process with PID {self.libfuzzer_process.pid} not found in system despite poll() == None")
                            process_running = False
                
                if not process_running:
                    # 프로세스가 종료된 경우 처리 (기존 코드)
                    # ...
                    pass
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
                                time.sleep(2)  # 더 긴 대기 시간
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
                    
                    # 실행 횟수(total_execs)가 0이고 프로세스가 실행 중이면 값 추정
                    if self.stats.get("total_execs", 0) == 0 and process_running:
                        # 추정 전략 1: exec_speed가 있으면 시간 × 속도로 추정
                        if "exec_speed" in self.stats and self.stats["exec_speed"] > 0:
                            elapsed = current_time - self.stats["start_time"]
                            estimated_execs = max(10, int(elapsed * self.stats["exec_speed"] / 2))
                            self.stats["total_execs"] = estimated_execs
                            logger.info(f"[LibFuzzer] Estimated execution count: {estimated_execs} (based on speed and time)")
                        # 추정 전략 2: corpus_size × 10으로 추정
                        elif corpus_size > 0:
                            estimated_execs = corpus_size * 10
                            self.stats["total_execs"] = estimated_execs
                            logger.info(f"[LibFuzzer] Estimated execution count: {estimated_execs} (based on corpus size)")
                        # 추정 전략 3: 기본값 100 사용
                        else:
                            self.stats["total_execs"] = 100
                            logger.info("[LibFuzzer] Using default execution count: 100")

                # 10초마다 상태 로깅
                if current_time - last_stats_print_time > 10:
                    with self.stats_lock:
                        elapsed = current_time - self.stats["start_time"]
                        execs = self.stats.get("total_execs", 0)
                        coverage = self.stats.get("coverage", 0)
                        crashes = self.stats.get("crashes_found", 0)
                        
                        # 디버그용 상태 로그
                        logger.debug(f"[Thread] Stats: elapsed={elapsed:.1f}s, execs={execs}, cov={coverage}, crashes={crashes}, corpus={corpus_size}")
                    
                    last_stats_print_time = current_time

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
        logger.info(f"[Thread] LLM call settings: stagnation_threshold={self.coverage_stagnation_threshold}s, call_interval={self.llm_call_interval}s")
        
        # 초기 상태 로깅
        logger.info(f"[Thread] LLM worker initial state: last_coverage={self.last_coverage}, "
                f"last_coverage_change_time={time.time() - self.last_coverage_change_time:.1f}s ago, "
                f"last_llm_call_time={time.time() - self.last_llm_call_time:.1f}s ago")
        
        # 첫 번째 호출을 위한 타이머
        first_call_timer = time.time()
        first_call_delay = 30  # 30초 후 첫 호출
        force_first_call = True

        while not self.stop_event.is_set():
            try:
                # 현재 커버리지 확인
                current_coverage = 0
                with self.stats_lock:
                    current_coverage = self.stats["coverage"]
                
                # 현재 시간
                current_time = time.time()
                
                # 초기 커버리지가 0인 경우, 정체 시간을 0으로 리셋하는 로직 추가
                if current_coverage > 0 and self.last_coverage == 0:
                    logger.info(f"[LLM] Initial coverage detected: {current_coverage}. Updating reference values.")
                    self.last_coverage = current_coverage
                    self.last_coverage_change_time = current_time
                
                # 커버리지 변화 확인
                if current_coverage > self.last_coverage:
                    logger.info(f"[LLM] Coverage increased from {self.last_coverage} to {current_coverage}")
                    self.last_coverage = current_coverage
                    self.last_coverage_change_time = current_time
                
                # 커버리지 정체 시간 계산
                coverage_stagnation_time = current_time - self.last_coverage_change_time
                # 마지막 LLM 호출 이후 시간 계산
                time_since_last_call = current_time - self.last_llm_call_time
                
                # 첫 번째 호출 강제 트리거
                first_call_condition = force_first_call and (current_time - first_call_timer >= first_call_delay) and current_coverage > 0
                
                # 정기적으로 상태 로깅 (10초마다)
                if int(current_time) % 10 == 0:
                    logger.info(f"[LLM] Status check: coverage={current_coverage}, "
                            f"stagnation_time={coverage_stagnation_time:.1f}s/{self.coverage_stagnation_threshold}s, "
                            f"time_since_last_call={time_since_last_call:.1f}s/{self.llm_call_interval}s, "
                            f"force_first_call={force_first_call and (current_time - first_call_timer >= first_call_delay)}")
                
                # LLM 호출 조건: 
                # 1. 커버리지가 지정 시간 이상 정체되었고 마지막 LLM 호출 후 지정 시간 이상 지났을 때
                # 2. 또는 첫 번째 호출 조건이 충족됐을 때
                if ((coverage_stagnation_time >= self.coverage_stagnation_threshold and 
                    time_since_last_call >= self.llm_call_interval) or first_call_condition):
                    
                    if first_call_condition:
                        logger.info(f"[LLM] First call condition triggered after {current_time - first_call_timer:.1f}s")
                        force_first_call = False  # 첫 호출 후 강제 트리거 비활성화
                    else:
                        logger.info(f"[LLM] Regular conditions met! Coverage stagnated for {coverage_stagnation_time:.1f}s, "
                                f"last LLM call was {time_since_last_call:.1f}s ago.")
                    
                    logger.info("[LLM] Trying LLM generation...")
                    
                    # API 한도 체크
                    if self.free_tier_only:
                        api_limits_ok = self._check_api_limits()
                        logger.info(f"[LLM] API limits check result: {api_limits_ok}")
                        
                        if not api_limits_ok:
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
                    if coverage_stagnation_time < self.coverage_stagnation_threshold:
                        logger.debug(f"[LLM] Coverage still changing, waiting... "
                                f"(Last change: {coverage_stagnation_time:.1f}s ago, need {self.coverage_stagnation_threshold}s)")
                    elif time_since_last_call < self.llm_call_interval:
                        logger.debug(f"[LLM] Last LLM call was too recent ({time_since_last_call:.1f}s ago), "
                                    f"waiting until {(self.llm_call_interval - time_since_last_call):.1f}s more...")
                    
                    # 대기 시간 (로그 과부하 방지)
                    time.sleep(5)  # 5초 대기로 줄임 (더 자주 체크)

            except Exception as e:
                logger.error(f"[LLM] Worker error: {e}")
                import traceback
                logger.error(f"[LLM] Worker error traceback: {traceback.format_exc()}")
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
    Now generate at least 20 NEW and DIVERSE valid WAT modules that strictly follow all rules,
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

    def setup_dashboard(self):
        """curses 기반 CLI 대시보드 설정"""
        self.use_dashboard = True
        self.screen = None
        
        # 대시보드 색상 설정
        self.colors = {
            'normal': 1,
            'green': 2,
            'yellow': 3,
            'red': 4,
            'cyan': 5,
            'magenta': 6,
            'blue': 7
        }
        
        # 로그 버퍼 (대시보드에 표시할 최근 로그)
        self.log_buffer = []
        self.max_log_lines = 10
        
        # 상태 업데이트 플래그
        self.need_redraw = True
        
        # 대시보드 타이머 (업데이트 주기)
        self.last_dashboard_update = 0
        self.dashboard_update_interval = 0.5  # 초
        
        # 로그 파일로 로그 리디렉션
        self.logs_file = os.path.join(os.path.dirname(self.corpus_dir), "fuzzer_logs.txt")
        
        # 기존 로그 핸들러를 파일 핸들러로 대체
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
        
        file_handler = logging.FileHandler(self.logs_file)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(file_handler)
        
        # 커스텀 로그 핸들러 추가 (로그 버퍼에 로그 추가)
        log_buffer_handler = LogBufferHandler(self)
        logger.addHandler(log_buffer_handler)
        
        logger.info("[Dashboard] Setup complete")

    def start_dashboard(self):
        """curses 대시보드 시작"""
        if not self.use_dashboard:
            return
        
        # curses 초기화
        self.screen = curses.initscr()
        
        # 키 입력 처리 설정
        curses.noecho()
        curses.cbreak()
        self.screen.keypad(True)
        self.screen.nodelay(True)  # 입력 대기 없이 즉시 반환
        
        # 색상 설정
        curses.start_color()
        curses.use_default_colors()
        
        # 색상 쌍 초기화
        curses.init_pair(self.colors['normal'], curses.COLOR_WHITE, -1)
        curses.init_pair(self.colors['green'], curses.COLOR_GREEN, -1)
        curses.init_pair(self.colors['yellow'], curses.COLOR_YELLOW, -1)
        curses.init_pair(self.colors['red'], curses.COLOR_RED, -1)
        curses.init_pair(self.colors['cyan'], curses.COLOR_CYAN, -1)
        curses.init_pair(self.colors['magenta'], curses.COLOR_MAGENTA, -1)
        curses.init_pair(self.colors['blue'], curses.COLOR_BLUE, -1)
        
        # 마우스 이벤트 활성화
        curses.mousemask(1)
        
        # 초기 화면 그리기
        self.draw_dashboard()
        
        # 대시보드 워커 스레드 시작
        dashboard_thread = threading.Thread(
            target=self.dashboard_worker,
            name="Dashboard-Worker",
            daemon=True
        )
        dashboard_thread.start()
        
        logger.info("[Dashboard] Started")
        return dashboard_thread

    def stop_dashboard(self):
        """curses 대시보드 종료"""
        if not self.use_dashboard or not self.screen:
            return
        
        # curses 설정 원복
        self.screen.keypad(False)
        curses.echo()
        curses.nocbreak()
        curses.endwin()
        
        self.screen = None
        logger.info("[Dashboard] Stopped")

    def draw_dashboard(self):
        """대시보드 그리기"""
        if not self.screen:
            return
        
        try:
            # 화면 크기 가져오기
            max_y, max_x = self.screen.getmaxyx()
            
            # 화면 지우기
            self.screen.clear()
            
            # 헤더 그리기
            self.draw_header(0, 0, max_x)
            
            # 통계 그리기
            self.draw_stats(2, 0, max_x)
            
            # 로그 섹션 그리기
            log_start_y = 15
            self.draw_logs(log_start_y, 0, max_x, max_y - log_start_y)
            
            # 화면 업데이트
            self.screen.refresh()
            self.need_redraw = False
            
        except Exception as e:
            logger.error(f"[Dashboard] Draw error: {e}")
            import traceback
            logger.error(f"[Dashboard] Traceback: {traceback.format_exc()}")

    def draw_header(self, y, x, width):
        """헤더 섹션 그리기"""
        # 경과 시간 계산
        elapsed = time.time() - self.stats["start_time"]
        days, remainder = divmod(int(elapsed), 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        # 헤더 라인 (honggfuzz 스타일)
        header_text = f"[{days:2d} days {hours:02d} hrs {minutes:02d} mins {seconds:02d} secs ]-------/ HybridFuzzer /-"
        header = "-" * 20 + header_text + "-" * max(0, width - len(header_text) - 20)
        
        # 헤더 출력
        self.screen.addstr(y, x, header[:width-1])

    def draw_stats(self, y, x, width):
        """통계 섹션 그리기"""
        with self.stats_lock:
            # 클론된 통계 가져오기 (복사본 생성)
            stats = self.stats.copy()
        
        # CPU 및 속도 값 가져오기
        cpu_percent = stats.get("cpu_percent", 0)
        cpu_per_core = stats.get("cpu_per_core", 0)
        exec_speed = stats.get("exec_speed", 0) 
        avg_exec_speed = stats.get("avg_exec_speed", 0)
        
        # 통계 라인 관련 정보
        stats_items = [
            ("Iterations", f"{stats.get('total_execs', 0)} [{stats.get('total_execs', 0)/1000:.2f}k]"),
            ("Mode", f"Hybrid Fuzzing (LibFuzzer + LLM)", self.colors['green']),
            ("Target", f"'{self.target_path}'"),
            ("Threads", f"{stats.get('libfuzzer_runs', 0)}+{stats.get('llm_runs', 0)}, PID: {os.getpid()}, CPU%: {cpu_percent}% ({cpu_per_core}%/CPU)"),
            ("Speed", f"{exec_speed}/sec (avg: {avg_exec_speed})", self.colors['blue']),
            ("Crashes", f"{stats.get('crashes_found', 0)}", self.colors['red']),
            ("Corpus Size", f"entries: {stats.get('corpus_size', 0)}", self.colors['cyan']),
            ("API Usage", f"{stats.get('api_requests', 0)}/{stats.get('api_free_tier_limit', 0)} requests"),
            ("API Reset", f"{self.free_tier_limits['reset_time'].strftime('%Y-%m-%d %H:%M:%S')}"),
            ("Coverage", f"paths: {stats.get('coverage', 0)}", self.colors['yellow']),
            ("WAT Compilation", f"success: {stats.get('wat_compile_success', 0)}, errors: {stats.get('wat_compile_errors', 0)}", 
            self.colors['magenta']),
        ]

        # 통계 출력
        for i, stat_item in enumerate(stats_items):
            label = stat_item[0].rjust(15) + " : "
            value = stat_item[1]
            color = stat_item[2] if len(stat_item) > 2 else self.colors['normal']
            
            # 라벨 출력
            self.screen.addstr(y + i, x, label)
            
            # 값 출력 (색상 적용)
            self.screen.addstr(y + i, x + len(label), str(value)[:width-len(label)-1], 
                            curses.color_pair(color))

    def draw_logs(self, y, x, width, height):
        """로그 섹션 그리기"""
        # 로그 섹션 제목
        log_header = "-" * 35 + " [ LOGS ] " + "-" * 35
        self.screen.addstr(y, x, log_header[:width-1])
        
        # 가능한 최대 로그 라인 수 계산
        max_lines = min(height - 2, len(self.log_buffer))
        
        # 로그 버퍼에서 최근 로그 선택
        logs_to_show = self.log_buffer[-max_lines:] if max_lines > 0 else []
        
        # 로그 출력
        for i, log_entry in enumerate(logs_to_show):
            if y + i + 2 >= y + height:
                break
                
            log_text = log_entry['message']
            log_level = log_entry['level']
            
            # 로그 레벨에 따른 색상 선택
            color = self.colors['normal']
            if 'CRASH' in log_text or 'ERROR' in log_text or log_level >= logging.ERROR:
                color = self.colors['red']
            elif 'WARNING' in log_text or log_level >= logging.WARNING:
                color = self.colors['yellow']
            elif '[LLM]' in log_text:
                color = self.colors['cyan']
            elif '[Thread]' in log_text:
                color = self.colors['magenta']
            elif '[LibFuzzer]' in log_text:
                color = self.colors['green']
            
            # 로그 텍스트 출력 (너무 길면 자르기)
            try:
                self.screen.addstr(y + i + 2, x, log_text[:width-1], curses.color_pair(color))
            except:
                # 오류 발생 시 안전하게 처리 (일반적으로 경계 문제)
                pass

    def dashboard_worker(self):
        """대시보드 업데이트 및 키 입력 처리"""
        logger.info("[Dashboard] Worker started")
        
        try:
            while not self.stop_event.is_set() and self.screen:
                current_time = time.time()
                
                # 화면 갱신 조건 확인
                if self.need_redraw or current_time - self.last_dashboard_update > self.dashboard_update_interval:
                    self.draw_dashboard()
                    self.last_dashboard_update = current_time
                
                # 키 입력 처리
                try:
                    key = self.screen.getch()
                    if key != -1:
                        self.handle_key(key)
                except:
                    pass
                    
                # CPU 점유율 최적화를 위한 짧은 대기
                time.sleep(0.1)
        
        except Exception as e:
            logger.error(f"[Dashboard] Worker error: {e}")
            import traceback
            logger.error(f"[Dashboard] Traceback: {traceback.format_exc()}")
        
        finally:
            logger.info("[Dashboard] Worker stopped")

    def handle_key(self, key):
        """키 입력 처리"""
        # q: 종료
        if key == ord('q'):
            logger.info("[Dashboard] Quit requested by user")
            self.stop_event.set()
        
        # r: 화면 갱신
        elif key == ord('r'):
            self.need_redraw = True
        
        # 기타 명령어...
        # TODO: 더 많은 단축키 추가

    def add_log(self, message, level=logging.INFO):
        """로그 버퍼에 로그 추가"""
        if len(self.log_buffer) >= self.max_log_lines:
            self.log_buffer.pop(0)
        
        self.log_buffer.append({
            'message': message,
            'level': level,
            'time': time.time()
        })
        
        self.need_redraw = True

class LogBufferHandler(logging.Handler):
    """로그 메시지를 대시보드 버퍼에 추가하는 핸들러"""
    
    def __init__(self, dashboard):
        super().__init__()
        self.dashboard = dashboard
    
    def emit(self, record):
        try:
            # 로그 메시지 포맷팅
            message = self.format(record)
            # 메시지가 너무 길면 자르기
            short_message = message[-100:] if len(message) > 100 else message
            # 대시보드 로그 버퍼에 추가
            self.dashboard.add_log(short_message, record.levelno)
        except Exception:
            self.handleError(record)

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
    parser.add_argument('--confirm-requests', action='store_true', default=False, help='Confirm API requests before sending')
    parser.add_argument('--free-tier-only', action='store_true', default=True, help='Respect free tier API limits')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable debug output')
    parser.add_argument('--llm-test', action='store_true', help='Only test LLM functionality without starting LibFuzzer')
    parser.add_argument('--dashboard', action='store_true', help='Enable CLI dashboard')

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
            if args.dashboard and hasattr(fuzzer, 'screen') and fuzzer.screen:
                fuzzer.stop_dashboard()  # 대시보드 정리
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

    # 대시보드 설정 (fuzzer 객체 생성 후)
    dashboard_thread = None
    if args.dashboard:
        try:
            # 대시보드 설정
            fuzzer.setup_dashboard()
            dashboard_thread = fuzzer.start_dashboard()
            logger.info("[MAIN] Dashboard started successfully")
        except Exception as e:
            logger.error(f"[Dashboard] Setup failed: {e}")
            logger.warning("[Dashboard] Running without dashboard")
            import traceback
            logger.debug(f"[Dashboard] Error trace: {traceback.format_exc()}")

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

    # 종료 전 대시보드 정리
    if args.dashboard and hasattr(fuzzer, 'screen') and fuzzer.screen:
        fuzzer.stop_dashboard()

if __name__ == "__main__":
    main()
