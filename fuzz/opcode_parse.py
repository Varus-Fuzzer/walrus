import re
import os

input_path = os.path.join('..', 'third_party', 'wabt', 'include', 'wabt', 'opcode.def')
output_path = os.path.join('./generated_opcode.txt')

pattern = re.compile(
    r'WABT_OPCODE\([^,]+,\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*'
    r'(?P<prefix>0x[0-9A-Fa-f]+|\d+),\s*'
    r'(?P<code>0x[0-9A-Fa-f]+|\d+),\s*'
    r'(?P<name>[A-Za-z0-9_]+),'
)

def generate_inline_functions(input_file, output_file):
    count = 0
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
        for line in infile:
            match = pattern.search(line)
            if match:
                prefix = match.group('prefix')
                code = match.group('code')
                name = match.group('name')
                prefix_val = int(prefix, 16) if prefix.startswith('0x') else int(prefix)
                code_val = int(code, 16) if code.startswith('0x') else int(code)
                full_val = (prefix_val << 8) | code_val
                outfile.write(f'inline Op Binaryen{name}() {{ return 0x{full_val:04X}; }}\n')
                count += 1
    print(f'Generated {count} inline functions in {output_file}')

generate_inline_functions(input_path, output_path)

with open(output_path, 'r') as f:
    for _ in range(10):
        print(f.readline().rstrip())