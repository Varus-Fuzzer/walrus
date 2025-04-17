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

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class HybridFuzzer:
    """
    Hybrid Fuzzer that uses LibFuzzer + LLM to generate WAT (WebAssembly Text) inputs.
    Modified to maintain a continuous LibFuzzer process for accumulated coverage.
    """

    def __init__(
        self,
        target_path: str,
        corpus_dir: str,
        libfuzzer_options: dict = None,
        llm_model: str = "llama3",
        llm_temperature: float = 0.7,
        libfuzzer_cycles: int = 1,  # 이제 사용하지 않음 (하위 호환성)
        llm_cycles: int = 1,
    ):
        self.target_path = os.path.abspath(target_path)
        self.corpus_dir = os.path.abspath(corpus_dir)
        self.crashes_dir = os.path.join(os.path.dirname(self.corpus_dir), "crashes")
        self.libfuzzer_options = libfuzzer_options or {}
        self.llm_model = llm_model
        self.llm_temperature = llm_temperature
        self.llm_cycles = llm_cycles

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

        self.ollama_host = os.environ.get("OLLAMA_HOST", "http://host.docker.internal:11434")
        logger.info(f"[INIT] Ollama API host: {self.ollama_host}")

        # Ollama 모델 확인
        try:
            response = requests.get(f"{self.ollama_host}/api/tags", timeout=5)
            if response.status_code == 200:
                models = response.json().get("models", [])
                avail_models = [m["name"] for m in models]
                if self.llm_model in avail_models:
                    logger.info(f"[INIT] Ollama model '{self.llm_model}' is available")
                else:
                    logger.warning(f"[INIT] Model '{self.llm_model}' not found. Available: {avail_models}")
            else:
                logger.warning(f"[INIT] Failed to connect to Ollama API (status={response.status_code})")
        except requests.RequestException as e:
            logger.error(f"[INIT] Ollama API connection error: {e}")
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
            "recent_new_coverage": []  # 최근 발견된 커버리지 정보
        }

    def start_continuous_libfuzzer(self):
        """
        커버리지가 누적될 수 있도록 LibFuzzer를 지속적으로 실행합니다.
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
                "-print_new_pcs=1"       # 새로운 PC 출력 (커버리지 정보 수집용)
            ]

            # 시간 제한 제거 (지속적 실행을 위해)
            # max_total_time 옵션은 추가하지 않음

            for k, v in self.libfuzzer_options.items():
                if k != "max_total_time":  # 시간 제한 옵션은 건너뜀
                    options.append(f"-{k}={v}")

            cmd = [self.target_path] + options + [self.corpus_dir]
            logger.debug(f"[LibFuzzer] Command: {' '.join(cmd)}")

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

            logger.info(f"[LibFuzzer] Continuous process started with PID: {self.libfuzzer_process.pid}")
            return self.libfuzzer_process.pid

    def _monitor_libfuzzer_output(self, pipe):
        """
        LibFuzzer 프로세스의 출력을 모니터링하고 통계를 업데이트합니다.
        """
        for line in iter(pipe.readline, ''):
            if not line:
                break

            # 크래시 발견 시 통계 업데이트
            if "stat::found_crash" in line:
                try:
                    val = int(line.split(":")[-1].strip())
                    with self.stats_lock:
                        self.stats["crashes_found"] += val
                        logger.info(f"[LibFuzzer] New crash found! Total: {self.stats['crashes_found']}")
                except ValueError:
                    pass

            # 실행 수 업데이트
            elif "stat::number_of_executed_units" in line:
                try:
                    val = int(line.split(":")[-1].strip())
                    with self.stats_lock:
                        self.stats["total_execs"] = val
                except ValueError:
                    pass

            # 코퍼스 크기 업데이트
            elif "stat::corpus_size" in line:
                try:
                    val = int(line.split(":")[-1].strip())
                    with self.stats_lock:
                        self.stats["corpus_size"] = val
                except ValueError:
                    pass

            # 커버리지 관련 정보 (Covered PCs)
            elif "cov:" in line:
                try:
                    cov_part = line.split("cov:")[1].split()[0]
                    val = int(cov_part)
                    with self.stats_lock:
                        self.stats["coverage"] = val
                except (ValueError, IndexError):
                    pass
                    
            # 새로운 PC(커버리지) 발견 정보 수집
            elif "NEW_PC:" in line:
                try:
                    pc_info = line.strip()
                    with self.stats_lock:
                        # 최근 10개의 새 커버리지 정보만 유지
                        self.stats["recent_new_coverage"].append(pc_info)
                        if len(self.stats["recent_new_coverage"]) > 10:
                            self.stats["recent_new_coverage"].pop(0)
                except Exception:
                    pass

            # 기타 중요 메시지 로깅
            elif any(x in line for x in ["CRASH", "ERROR", "WARNING", "NEW_FUNC", "NEW_PC"]):
                logger.info(f"[LibFuzzer] {line.strip()}")
            else:
                logger.debug(f"[LibFuzzer] {line.strip()}")

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
        """
        logger.info("[Thread] LibFuzzer worker started")

        try:
            # 초기 프로세스 시작
            self.start_continuous_libfuzzer()

            while not self.stop_event.is_set():
                # 테스트케이스 큐 처리
                self.process_queue_testcases()

                # 프로세스 상태 확인
                with self.libfuzzer_process_lock:
                    if self.libfuzzer_process is None or self.libfuzzer_process.poll() is not None:
                        # 프로세스가 종료된 경우 재시작
                        logger.warning("[Thread] LibFuzzer process exited unexpectedly, restarting...")
                        self.start_continuous_libfuzzer()

                # 통계 업데이트 및 출력
                with self.stats_lock:
                    corpus_size = len(os.listdir(self.corpus_dir))
                    crashes_count = len(os.listdir(self.crashes_dir))
                    self.stats["corpus_size"] = corpus_size
                    self.stats["crashes_count"] = crashes_count

                # 주기적인 상태 체크 간격
                time.sleep(5)

        except Exception as e:
            logger.error(f"[Thread] LibFuzzer worker error: {e}")
        finally:
            logger.info("[Thread] LibFuzzer worker stopping")
            self.stop_libfuzzer()

    def llm_worker_thread(self):
        """
        LLM을 사용하여 새로운 테스트 케이스를 생성하는 워커 스레드
        """
        logger.info("[Thread] LLM worker started")

        while not self.stop_event.is_set():
            try:
                samples = self.get_interesting_inputs(limit=5)
                if not samples:
                    logger.info("[LLM] No sample found in the corpus, waiting...")
                    time.sleep(5)
                    continue

                generated_wat = self.generate_llm_inputs(samples)
                if not generated_wat:
                    logger.warning("[LLM] Failed to generate new inputs, waiting...")
                    time.sleep(5)
                    continue

                saved_count = self.save_inputs_to_corpus(generated_wat)

                with self.stats_lock:
                    self.stats["llm_runs"] += 1

                logger.info(f"[LLM] LLM input generation completed: {len(generated_wat)} generated, {saved_count} saved")

                time.sleep(3)

            except Exception as e:
                logger.error(f"[LLM] Worker error: {e}")
                time.sleep(5)

    def generate_llm_inputs(self, prompt_inputs: list) -> list:
        """
        LLM을 사용하여 새로운 WAT 모듈을 생성합니다.
        """
        logger.info("[LLM] Requesting new inputs from Ollama")

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

        request_data = {
            "model": self.llm_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": self.llm_temperature,
            "stream": False
        }

        try:
            resp = requests.post(
                f"{self.ollama_host}/api/chat",
                json=request_data,
                timeout=120
            )
            if resp.status_code != 200:
                logger.error(f"[LLM] HTTP status {resp.status_code}, response: {resp.text}")
                return []

            data = resp.json()
            generated_text = data.get("message", {}).get("content", "")
            if not generated_text.strip():
                return []

            # 디버깅: LLM이 생성한 원시 텍스트 출력
            logger.debug(f"[LLM Debug] Raw generated text:\n{generated_text}")

           # 모듈 추출
            pattern = r'@MODULE_START\s*(.*?)\s*@MODULE_END'
            matches = re.findall(pattern, generated_text, flags=re.DOTALL)
            if not matches:
                # fallback
                module_pattern = r'(\(module.*?\))'
                matches = re.findall(module_pattern, generated_text, flags=re.DOTALL)

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

            return valid_results

        except Exception as e:
            logger.error(f"[LLM] Request error: {e}")
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
                        os.remove(wat_file)
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
                        
                        os.remove(wat_file)
                except Exception as e:
                    logger.error(f"[LLM] wat2wasm conversion error: {e}")
                    os.remove(wat_file)
            else:
                logger.warning("[LLM] wat2wasm not installed => discarding .wat")
                os.remove(wat_file)

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

    def run(self, total_time: int = 3600) -> dict:
        """
        지속적인 커버리지 축적을 위해 수정된 실행 메서드
        에러 피드백 및 커버리지 정보 공유 기능 포함
        """
        logger.info(f"[RUN] Starting enhanced hybrid fuzzing (total time: {total_time}s)")
        logger.info(f"[RUN] Error feedback: {'Enabled' if self.max_error_history > 0 else 'Disabled'}")

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

            return self.stats
    
def main():
    parser = argparse.ArgumentParser(description='LibFuzzer+LLM Hybrid Fuzzer with continuous fuzzing, improved WAT prompt, and error feedback.')
    parser.add_argument('--target', '-t', required=True, help='Path to the Walrus fuzzing target')
    parser.add_argument('--corpus', '-c', required=True, help='Corpus directory')
    parser.add_argument('--time', type=int, default=3600, help='Total fuzzing time (seconds)')
    parser.add_argument('--libfuzzer-cycles', type=int, default=1, help='DEPRECATED: Now use single LibFuzzer process for better coverage accumulation')
    parser.add_argument('--llm-cycles', type=int, default=1, help='Number of parallel LLM workers')
    parser.add_argument('--llm-model', default='llama3', help='Name of the Ollama model')
    parser.add_argument('--ollama-host', help='Ollama API host (default: http://host.docker.internal:11434)')
    parser.add_argument('--libfuzzer-options', help='LibFuzzer options (JSON)')
    parser.add_argument('--max-error-history', type=int, default=3, help='Maximum number of error feedback items to store for LLM')
    parser.add_argument('--feedback-enabled', action='store_true', default=True, help='Enable error feedback to LLM')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable debug output')

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if args.ollama_host:
        os.environ["OLLAMA_HOST"] = args.ollama_host

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
    )
    
    # 에러 피드백 설정 적용
    if args.feedback_enabled:
        fuzzer.max_error_history = args.max_error_history
    else:
        # 피드백 비활성화
        fuzzer.max_error_history = 0
        fuzzer.wat_error_history = []

    logger.info("[MAIN] Starting HybridFuzzer with continuous LibFuzzer execution")
    logger.info(f"[MAIN] Error feedback is {'enabled' if args.feedback_enabled else 'disabled'}")
    
    stats = fuzzer.run(total_time=args.time)

    # 최종 결과 출력
    print(json.dumps(stats, indent=2))
    
    # 통계 로깅
    logger.info("=== WAT Compilation Statistics ===")
    logger.info(f"Total WAT compilation attempts: {stats['wat_compile_success'] + stats['wat_compile_errors']}")
    logger.info(f"Successful WAT compilations: {stats['wat_compile_success']}")
    logger.info(f"Failed WAT compilations: {stats['wat_compile_errors']}")
    
    if stats['wat_compile_errors'] > 0 and stats['wat_compile_success'] > 0:
        success_rate = (stats['wat_compile_success'] / 
                        (stats['wat_compile_success'] + stats['wat_compile_errors'])) * 100
        logger.info(f"WAT compilation success rate: {success_rate:.2f}%")

if __name__ == "__main__":
    main()
