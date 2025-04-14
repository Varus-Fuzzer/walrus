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

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class HybridFuzzer:
    """
    Hybrid Fuzzer that uses LibFuzzer + LLM to generate WAT (WebAssembly Text) inputs.
    The prompt has been modified to produce valid WAT and filter out invalid ones.
    """

    def __init__(
        self,
        target_path: str,
        corpus_dir: str,
        libfuzzer_options: dict = None,
        llm_model: str = "llama3",
        llm_temperature: float = 0.7,
        libfuzzer_cycles: int = 2,
        llm_cycles: int = 1,
    ):
        self.target_path = os.path.abspath(target_path)
        self.corpus_dir = os.path.abspath(corpus_dir)
        self.crashes_dir = os.path.join(os.path.dirname(self.corpus_dir), "crashes")
        self.libfuzzer_options = libfuzzer_options or {}
        self.llm_model = llm_model
        self.llm_temperature = llm_temperature
        self.libfuzzer_cycles = libfuzzer_cycles
        self.llm_cycles = llm_cycles

        self.corpus_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.stats_lock = threading.Lock()

        os.makedirs(self.corpus_dir, exist_ok=True)
        os.makedirs(self.crashes_dir, exist_ok=True)

        self.ollama_host = os.environ.get("OLLAMA_HOST", "http://host.docker.internal:11434")
        logger.info(f"[INIT] Ollama API host: {self.ollama_host}")

        # Check Ollama model
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

    def run_libfuzzer(self, time_limit: int = 60) -> dict:
        logger.info(f"[LibFuzzer] Starting cycle (limit {time_limit}s)")

        options = [
            f"-max_total_time={time_limit}",
            f"-artifact_prefix={self.crashes_dir}{os.sep}",
            "-print_final_stats=1"
        ]
        for k, v in self.libfuzzer_options.items():
            options.append(f"-{k}={v}")

        cmd = [self.target_path] + options + [self.corpus_dir]
        logger.debug(f"[LibFuzzer] Command: {' '.join(cmd)}")

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        stdout, stderr = process.communicate()
        output = stderr if stderr else stdout

        result = {
            "return_code": process.returncode,
            "output": output,
            "crashes_found": 0,
            "executions": 0,
            "corpus_size": len(os.listdir(self.corpus_dir))
        }

        for line in output.splitlines():
            if "stat::number_of_executed_units" in line:
                try:
                    val = int(line.split(":")[-1].strip())
                    result["executions"] = val
                except ValueError:
                    pass
            elif "stat::found_crash" in line:
                try:
                    val = int(line.split(":")[-1].strip())
                    result["crashes_found"] = val
                except ValueError:
                    pass

        with self.stats_lock:
            self.stats["libfuzzer_runs"] += 1
            self.stats["total_execs"] += result["executions"]
            self.stats["crashes_found"] += result["crashes_found"]

        logger.info(f"[LibFuzzer] Completed: {result['executions']} execs, "
                    f"{result['crashes_found']} crash, "
                    f"corpus size: {result['corpus_size']}")

        return result

    def libfuzzer_worker_thread(self, cycle_time: int):
        logger.info("[Thread] LibFuzzer worker started")
        cycle_count = 0

        while not self.stop_event.is_set():
            try:
                cycle_count += 1
                logger.info(f"[Thread] LibFuzzer cycle #{cycle_count} started")
                self.run_libfuzzer(time_limit=cycle_time)

                # Drain the corpus queue so LibFuzzer sees new inputs
                while not self.corpus_queue.empty():
                    try:
                        new_input = self.corpus_queue.get_nowait()
                        logger.debug(f"[Thread] New input from LLM: {new_input}")
                        self.corpus_queue.task_done()
                    except queue.Empty:
                        break

                time.sleep(1)

            except Exception as e:
                logger.error(f"[Thread] LibFuzzer worker error: {e}")
                time.sleep(3)

    def llm_worker_thread(self):
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
        Save the LLM-generated WAT modules to the corpus directory.
        If wat2wasm is available, attempt to compile them to .wasm.
        Only keep them if the compilation succeeds and is not duplicate.
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
                        self.corpus_queue.put(wasm_file)
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
        try:
            proc = subprocess.run(["wat2wasm", "--version"], capture_output=True, timeout=2)
            return (proc.returncode == 0)
        except FileNotFoundError:
            return False
        except Exception:
            return False

    def get_interesting_inputs(self, limit: int = 5) -> list:
        """
        Fetch some sample inputs from the existing corpus to feed into the LLM as context.
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
        Convert a given binary data into a trivial WAT string. 
        If it's WASM, produce minimal (module ...) 
        otherwise treat it as i32.const segments.
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
        logger.info(f"[RUN] Starting hybrid fuzzing (total time: {total_time}s)")

        start_time = time.time()
        # cycle_time: libfuzzer 한 번 실행할 시간
        cycle_time = min(60, total_time // (self.libfuzzer_cycles * 2) or 30)

        threads = []

        # libfuzzer 스레드 시작
        for i in range(self.libfuzzer_cycles):
            th = threading.Thread(
                target=self.libfuzzer_worker_thread,
                args=(cycle_time,),
                name=f"LibFuzzer-Worker-{i+1}",
                daemon=True
            )
            threads.append(th)
            th.start()
            logger.info(f"[RUN] LibFuzzer worker #{i+1} started")

        # llm 스레드 시작
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
            while True:
                now = time.time()
                if now >= end_time:
                    break

                elapsed = now - start_time
                remaining = end_time - now

                # 10초마다 상태 출력
                if int(elapsed) % 10 == 0:
                    with self.stats_lock:
                        corpus_size = len(os.listdir(self.corpus_dir))
                        crashes_count = len(os.listdir(self.crashes_dir))
                        logger.info(f"[RUN] {elapsed:.1f}s elapsed (remaining {remaining:.1f}s), "
                                    f"Exec={self.stats['total_execs']}, "
                                    f"Crash={self.stats['crashes_found']}, "
                                    f"Corpus={corpus_size}")
                time.sleep(1)

        except KeyboardInterrupt:
            logger.info("[RUN] Stopped by user (Ctrl+C)")

        finally:
            logger.info("[RUN] Sending stop signal...")
            self.stop_event.set()
            for th in threads:
                th.join(timeout=5)
                if th.is_alive():
                    logger.warning(f"[RUN] Thread {th.name} did not exit in time.")

            with self.stats_lock:
                self.stats["total_time"] = time.time() - start_time
                self.stats["corpus_size"] = len(os.listdir(self.corpus_dir))
                self.stats["crashes_count"] = len(os.listdir(self.crashes_dir))

            logger.info("=== Fuzzing finished ===")
            logger.info(f"Total executions : {self.stats['total_execs']}")
            logger.info(f"Total crashes    : {self.stats['crashes_found']}")
            logger.info(f"Corpus size      : {self.stats['corpus_size']}")
            logger.info(f"Total run time   : {self.stats['total_time']:.2f}s")

            return self.stats
    
    


def main():
    parser = argparse.ArgumentParser(description='LibFuzzer+LLM Hybrid Fuzzer (thread-based) with improved WAT prompt.')
    parser.add_argument('--target', '-t', required=True, help='Path to the Walrus fuzzing target')
    parser.add_argument('--corpus', '-c', required=True, help='Corpus directory')
    parser.add_argument('--time', type=int, default=3600, help='Total fuzzing time (seconds)')
    parser.add_argument('--libfuzzer-cycles', type=int, default=2, help='Number of parallel LibFuzzer workers')
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

    libfuzzer_options = {}
    if args.libfuzzer_options:
        try:
            libfuzzer_options = json.loads(args.libfuzzer_options)
        except json.JSONDecodeError:
            logger.error("Error parsing LibFuzzer options - must be valid JSON.")
            sys.exit(1)


    try:
        subprocess.run(["wat2wasm", "--version"], capture_output=True)
        logger.info("[INIT] Found wat2wasm tool")
    except FileNotFoundError:
        logger.warning("[INIT] wat2wasm not installed - WAT text will be stored as-is")

    fuzzer = HybridFuzzer(
        target_path=args.target,
        corpus_dir=args.corpus,
        libfuzzer_options=libfuzzer_options,
        llm_model=args.llm_model,
        libfuzzer_cycles=args.libfuzzer_cycles,
        llm_cycles=args.llm_cycles,
    )

    stats = fuzzer.run(total_time=args.time)
    print(json.dumps(stats, indent=2))

if __name__ == "__main__":
    main()
