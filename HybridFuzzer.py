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
            "crashes_count": 0
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
                "-print_corpus_stats=1"  # 코퍼스 상태 출력
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
You are a WASM text format (WAT) generator.
Your job is to ONLY produce valid WebAssembly Text Format (WAT) modules
that can be compiled by 'wat2wasm' without errors.

---------------------------
[ CORE RULES ]
1. Each module must start with (module and end with ).
2. Inside the module, only use standard W3C WebAssembly instructions 
   and declarations, such as:
   - (func (export "name") (param $p i32) (result i32) ...)
   - (global $g (mut i32) (i32.const 0))
   - (memory (export "mem") 1)
   - (data (i32.const 0) "some string")
   - (table (export "tab") 1 10 funcref)
   - (type ...)
   - (elem ...)
   - instructions like local.get, local.set, i32.const, i32.add, i32.load, i32.store, call, call_indirect, block, loop, if, end, br, etc.

3. DO NOT use assembly directives (.text, .data, .globl, db, etc.).
4. DO NOT use Lisp-like syntax (define, lambda, define-export, define-adder, etc.).
5. DO NOT invent or introduce new tokens like ":", "=>", "[...]", or "()", or random punctuation.
6. If you add data segments, it must be in the form: (data (i32.const offset) "string").
   Also ensure (memory ...) is declared if you're storing data.
7. (global) or (local) must not be empty. Example:
   (global $g i32 (i32.const 10))
   (func (param $x i32) (local i32 i32) ...)
8. Only produce a single module per code block and do not produce anything outside (module ...).
9. No comments allowed at all.

---------------------------
[ AVOID COMMON ERRORS ]
10. NEVER use expressions like (i32.const 0) inside parameter or result definitions.
    ❌ Wrong: (param $x (i32.const 0))
    ❌ Wrong: (result (i32.const 1))
    ✅ Correct: (param $x i32)
    ✅ Correct: (result i32)

11. Only use (i32.const N) inside function bodies or global initializers, never in param/result type declarations.

12. (local $var i32) must NOT have immediate initialization like (local $var i32 (i32.const N)).
    To initialize a local variable, do:
      (local $var i32)
      i32.const N
      local.set $var

13. DO NOT use keywords like (age), (shareable), or random tokens for memory:
    The correct form is (memory (export "mem") 1 2) or (memory 1), etc. 
    (memory) must have numeric arguments or an export declaration with min/max pages.

14. (call $someLocalVar) is invalid. 'call' must reference a function name declared by (func $someFunc).
    Similarly, (call_indirect) uses a (table ...) and (type ...). 
    You cannot directly call local variables.

15. For tables, the correct minimal form is something like:
    (table (export "tab") 1 10 funcref)
    (elem (i32.const 0) $func1 $func2)
    (type $t (func (param i32) (result i32)))
    (call_indirect (type $t) (local.get $someIndex))

16. Double-check that every ( has a matching ), no extra or missing parentheses.
17. The output must be compileable by wat2wasm with no errors.

---------------------------
[ DIVERSITY & UNIQUENESS RULES ]
18. Do not copy function names, exports, memory sizes, or global names exactly from the examples.
19. Each module must include at least 2 instructions from { i32.load, i32.store, block, loop, if, local.set, i32.eq, i32.lt, i32.gt } that are NOT used in the example modules.
20. If you use tables or call_indirect, you must define and reference matching types and function(s) properly (no undefined function references).

---------------------------
[ NEW ADDITIONAL RULES ]
21. If you declare (elem (i32.const N) $f1 $f2 ...), you MUST define each of those functions in the same module:
    (func $f1 (param ...) (result ...) ...)
    (func $f2 ...)
    etc.

22. Standard W3C WebAssembly does not support tokens like local.add, local.sub, then, or endif.
    - You must use i32.add, i32.sub, etc. instead of local.add/local.sub.
    - If statement must use 'if'...'end' (and optional 'else'...'end'), not 'then' or 'endif'.
    - Compare instructions like i32.eq, i32.gt, etc. must use values from the stack, e.g.:
        i32.const 0
        i32.eq
      rather than i32.eq (i32.const 0).

---------------------------
[ EXAMPLES OF CORRECT MODULES (NO COMMENTS) ]

(module
  (global $g (mut i32) (i32.const 0))
  (memory (export "mem") 1)
  (data (i32.const 0) "Hello")
  (func (export "doubleX") (param $x i32) (result i32)
    local.get $x
    i32.const 2
    i32.mul
  )
)

(module
  (func (export "sumX") (param $a i32) (param $b i32) (result i32)
    local.get $a
    local.get $b
    i32.add
  )
)

(module
  (table (export "myTableX") 2 10 funcref)
  (type $t (func (param i32) (result i32)))
  (elem (i32.const 0) $f1 $f2)
  (func $f1 (param $p i32) (result i32)
    local.get $p
    i32.const 42
    i32.add
  )
  (func $f2 (param $p i32) (result i32)
    local.get $p
    i32.const 1
    i32.sub
  )
  (func (export "testIndirectX") (param $index i32) (result i32)
    local.get $index
    call_indirect (type $t)
  )
)

"""


        user_prompt = f"""
We already have some WAT samples for reference, such as:
{json.dumps(prompt_inputs, indent=2)}

Now generate at least 3 NEW and DIVERSE valid WAT modules that strictly follow all rules, 
including the DIVERSITY & UNIQUENESS RULES.

- You must use at least 2 instructions from the set {{ i32.load, i32.store, block, loop, if, local.set, i32.eq, i32.lt, i32.gt }} 
  in each module, different from the examples.
- Use different memory sizes, export names, function names, or table names than in the examples.
- Do not replicate the same structure or name from the provided examples.

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
                        os.remove(wat_file)
                        self.add_new_testcase(wasm_file)  # 변경: 새 테스트케이스 추가
                        saved += 1
                        # 새롭게 저장된 바이너리 파일도 해시에 추가
                        with open(wasm_file, "rb") as f:
                            new_hash = hashlib.sha256(f.read()).hexdigest()
                            existing_hashes.add(new_hash)
                    else:
                        logger.warning(f"[LLM] wat2wasm failed => discarding. stderr:\n{proc.stderr.decode('utf-8','replace')}")
                        os.remove(wat_file)
                except Exception as e:
                    logger.error(f"[LLM] wat2wasm conversion error: {e}")
                    os.remove(wat_file)
            else:
                logger.warning("[LLM] wat2wasm not installed => discarding .wat")
                os.remove(wat_file)

        return saved


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
        """
        paths = [os.path.join(self.corpus_dir, f) for f in os.listdir(self.corpus_dir)]
        if not paths:
            return []

        # 가장 최근 수정된 파일 일부
        paths = sorted(paths, key=os.path.getmtime, reverse=True)[:max(1, limit // 2)]
        remaining = limit - len(paths)

        # 추가로 나머지 무작위
        all_files = [os.path.join(self.corpus_dir, f) for f in os.listdir(self.corpus_dir)]
        extra_candidates = [p for p in all_files if p not in paths]
        if remaining > 0 and extra_candidates:
            chosen = random.sample(extra_candidates, min(remaining, len(extra_candidates)))
            paths += chosen

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
        WASM인 경우 최소한의 (module ...)을 생성하고,
        그렇지 않으면 i32.const 세그먼트로 취급합니다.
        """
        wat_lines = ["(module"]
        if len(binary_data) < 8 or binary_data[0:4] != b"\0asm":
            wat_lines.append("  ;; Not a standard .wasm => treat as i32.const")
            wat_lines.append("  (func (export \"fuzz_target\") (result i32)")
            for i in range(0, len(binary_data), 4):
                chunk = binary_data[i:i+4]
                if len(chunk) < 4:
                    chunk += b"\0"*(4-len(chunk))
                val = struct.unpack("<I", chunk)[0]
                wat_lines.append(f"    i32.const {val}")
                if i < len(binary_data)-4:
                    wat_lines.append("    drop")
            wat_lines.append("  )")
        else:
            wat_lines.append("  ;; Minimal parse: actual parse omitted.")
            wat_lines.append("  (func (export \"dummy\") )")
        wat_lines.append(")")
        return "\n".join(wat_lines)

    def run(self, total_time: int = 3600) -> dict:
        """
        지속적인 커버리지 축적을 위해 수정된 실행 메서드
        """
        logger.info(f"[RUN] Starting hybrid fuzzing (total time: {total_time}s)")
        
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
            
            return self.stats

def main():
    parser = argparse.ArgumentParser(description='LibFuzzer+LLM Hybrid Fuzzer with continuous fuzzing and improved WAT prompt.')
    parser.add_argument('--target', '-t', required=True, help='Path to the Walrus fuzzing target')
    parser.add_argument('--corpus', '-c', required=True, help='Corpus directory')
    parser.add_argument('--time', type=int, default=3600, help='Total fuzzing time (seconds)')
    parser.add_argument('--libfuzzer-cycles', type=int, default=1, help='DEPRECATED: Now use single LibFuzzer process for better coverage accumulation')
    parser.add_argument('--llm-cycles', type=int, default=1, help='Number of parallel LLM workers')
    parser.add_argument('--llm-model', default='llama3', help='Name of the Ollama model')
    parser.add_argument('--ollama-host', help='Ollama API host (default: http://host.docker.internal:11434)')
    parser.add_argument('--libfuzzer-options', help='LibFuzzer options (JSON)')
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

    logger.info("[MAIN] Starting HybridFuzzer with continuous LibFuzzer execution")
    stats = fuzzer.run(total_time=args.time)
    
    # 최종 결과 출력
    print(json.dumps(stats, indent=2))

if __name__ == "__main__":
    main()
