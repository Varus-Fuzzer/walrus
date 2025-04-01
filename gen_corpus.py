#!/usr/bin/env python3
import os
import shutil
import subprocess
import argparse

def find_wast_files(root_dir: str):
    wast_files = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        for filename in filenames:
            if filename.endswith(".wast"):
                full_path = os.path.join(dirpath, filename)
                wast_files.append(full_path)
    return wast_files

def copy_wast_files(wast_file_paths, root_dir: str, output_folder: str = "corpus_wast"):
    output_dir = os.path.join(root_dir, output_folder)
    os.makedirs(output_dir, exist_ok=True)
    for wast_path in wast_file_paths:
        filename = os.path.basename(wast_path)
        dest_path = os.path.join(output_dir, filename)
        shutil.copyfile(wast_path, dest_path)
        print(f"[COPY] {wast_path} -> {dest_path}")

def convert_wast_to_wasm(wast_file_paths, root_dir: str, output_folder: str = "corpus"):
    output_dir = os.path.join(root_dir, output_folder)
    os.makedirs(output_dir, exist_ok=True)
    for wast_path in wast_file_paths:
        filename = os.path.basename(wast_path)
        base_name, _ = os.path.splitext(filename)
        wasm_filename = base_name + ".wasm"
        wasm_path = os.path.join(output_dir, wasm_filename)
        with open(wast_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        filtered_lines = [ln for ln in lines if "assert_return" not in ln]
        process = subprocess.run(
            ["wat2wasm", "-", "-o", wasm_path],
            input="".join(filtered_lines),
            text=True
        )
        if process.returncode == 0:
            print(f"[OK] {wast_path} -> {wasm_path}")
        else:
            print(f"[FAIL] wat2wasm conversion failed for {wast_path}")

def main():
    parser = argparse.ArgumentParser(description="Convert .wast files to .wasm, removing assert_return lines.")
    parser.add_argument("--root-dir", default="/opt/Varus/walrus/test")
    args = parser.parse_args()
    root_directory = args.root_dir
    wast_paths = find_wast_files(root_directory)
    copy_wast_files(wast_paths, root_directory, "corpus_wast")
    convert_wast_to_wasm(wast_paths, root_directory, "corpus")

if __name__ == "__main__":
    main()
