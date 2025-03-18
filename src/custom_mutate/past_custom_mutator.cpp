#include <cstdint>
#include <cstring>
#include <vector>
#include <random>
#include <algorithm>

// Helper to read a LEB128-encoded unsigned 32-bit integer from data.
static uint32_t readVarU32(const uint8_t *data, size_t size, size_t &offset) {
    uint32_t result = 0;
    uint32_t shift = 0;
    while (offset < size) {
        uint8_t byte = data[offset++];
        result |= uint32_t(byte & 0x7F) << shift;
        if ((byte & 0x80) == 0) break;
        shift += 7;
    }
    return result;
}

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size, size_t MaxSize, unsigned int Seed) {
    // Step 1: Verify WASM header (magic number and version).
    const uint8_t WASM_MAGIC[4] = {0x00, 0x61, 0x73, 0x6d};
    const uint8_t WASM_VERSION[4] = {0x01, 0x00, 0x00, 0x00};
    if (Size < 8 || memcmp(Data, WASM_MAGIC, 4) != 0 || memcmp(Data+4, WASM_VERSION, 4) != 0) {
        // Input is not a valid WASM module. Provide a minimal valid WASM module as a dummy&#8203;:contentReference[oaicite:7]{index=7}.
        static const uint8_t dummy_module[] = {
            // WASM magic & version:
            0x00, 0x61, 0x73, 0x6d,  0x01, 0x00, 0x00, 0x00,
            // Type Section (ID=1):
            0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 
            // Function Section (ID=3):
            0x03, 0x02, 0x01, 0x00,
            // Code Section (ID=10):
            0x0A, 0x04, 0x01,       // code section header: length=4, count=1
            0x02, 0x00, 0x0B        // body size=2, local decl count=0, end opcode (0x0B)
        };
        size_t dummy_size = sizeof(dummy_module);
        if (dummy_size <= MaxSize) {
            memcpy(Data, dummy_module, dummy_size);
        }
        return dummy_size;
    }

    // Step 2: Parse section headers to identify key sections (type=1, function=3, global=6, code=10, data=11, etc.).
    struct Section { uint8_t id; size_t offset; uint32_t size; };
    std::vector<Section> sections;
    size_t offset = 8;  // start after header
    while (offset < Size) {
        if (offset + 1 > Size) break;
        uint8_t sec_id = Data[offset++];
        uint32_t sec_size = readVarU32(Data, Size, offset);
        if (sec_size > Size || offset + sec_size > Size) break;  // malformed length
        sections.push_back({sec_id, offset, sec_size});
        offset += sec_size;
    }
    // Locate specific sections of interest.
    const Section *typeSec = nullptr, *funcSec = nullptr, *globalSec = nullptr;
    const Section *codeSec = nullptr, *dataSec = nullptr;
    for (auto &sec : sections) {
        switch(sec.id) {
            case 1: typeSec = &sec; break;
            case 3: funcSec = &sec; break;
            case 6: globalSec = &sec; break;
            case 10: codeSec = &sec; break;
            case 11: dataSec = &sec; break;
            default: break;
        }
    }

    // Parse the code section to get function bodies (offset and length of each function's bytecode).
    struct FuncBody { size_t offset; uint32_t size; };
    std::vector<FuncBody> functions;
    if (codeSec) {
        size_t pos = codeSec->offset;
        uint32_t funcCount = readVarU32(Data, Size, pos);
        functions.reserve(funcCount);
        for (uint32_t i = 0; i < funcCount && pos < codeSec->offset + codeSec->size; ++i) {
            uint32_t bodySize = readVarU32(Data, Size, pos);
            size_t bodyStart = pos;
            pos += bodySize;  // skip the body bytes
            if (bodyStart + bodySize <= Size) {
                functions.push_back({ bodyStart, bodySize });
            } else {
                break; // malformed
            }
        }
    }

    // Step 3: Choose a random mutation strategy: instruction-level, constant tweak, or section-level.
    std::mt19937 rng(Seed);
    enum MutKind { MUT_CHANGE_INST, MUT_CHANGE_CONST, MUT_CHANGE_SECTION };
    MutKind kind;
    if (codeSec && !functions.empty()) {
        // If we have code to mutate, favor instruction or constant mutations 2:1 over section changes.
        kind = (MutKind)(rng() % 3);  // 0 or 1 => code mutations, 2 => section mutation
    } else {
        kind = MUT_CHANGE_SECTION;
    }

    switch (kind) {
    case MUT_CHANGE_INST: {
        // **Instruction mutation**: replace one opcode with a similar one (to preserve validity).
        const FuncBody &func = functions[rng() % functions.size()];
        // Parse the function body to find all instruction start positions.
        size_t inst_start = func.offset;
        // Skip local declarations (compressed in the body prefix).
        uint32_t localCount = readVarU32(Data, Size, inst_start);
        for (uint32_t li = 0; li < localCount && inst_start < func.offset + func.size; ++li) {
            uint32_t count = readVarU32(Data, Size, inst_start);
            if (inst_start < func.offset + func.size) inst_start += 1; // skip local type byte
        }
        // Collect positions of each instruction (start of opcode) in this function.
        std::vector<size_t> instr_positions;
        size_t pos = inst_start;
        while (pos < func.offset + func.size) {
            instr_positions.push_back(pos);
            uint8_t opcode = Data[pos++];
            if (opcode == 0x0B) {  // 0x0B = END of function/body
                break;
            }
            // Advance pos by the length of this instruction's immediate operands (if any).
            // We handle common cases (numeric const, call indices, br targets, memory ops, etc.).
            if ((opcode >= 0x41 && opcode <= 0x44)) {
                // i32.const/i64.const (LEB) or f32.const (4-byte) or f64.const (8-byte).
                if (opcode == 0x41 || opcode == 0x42) { // i32.const or i64.const use LEB128 (s32 or s64)
                    while (pos < func.offset + func.size && (Data[pos] & 0x80)) pos++;
                    pos++;  // consume the last byte of the LEB
                } else if (opcode == 0x43) {
                    pos += 4; // f32 immediate
                } else if (opcode == 0x44) {
                    pos += 8; // f64 immediate
                }
            } else if (opcode == 0x0C || opcode == 0x0D) {
                // br, br_if (immediate: depth as LEB)
                while (pos < func.offset + func.size && (Data[pos] & 0x80)) pos++;
                pos++;
            } else if (opcode == 0x10) {
                // call (immediate: function index as LEB)
                while (pos < func.offset + func.size && (Data[pos] & 0x80)) pos++;
                pos++;
            } else if (opcode == 0x11) {
                // call_indirect (immediate: type index LEB, plus reserved byte)
                while (pos < func.offset + func.size && (Data[pos] & 0x80)) pos++;
                pos++;
                pos++; // skip the reserved 0x00 for table index
            } else if (opcode >= 0x20 && opcode <= 0x24) {
                // local.get/set/tee or global.get/set (immediate: index LEB)
                while (pos < func.offset + func.size && (Data[pos] & 0x80)) pos++;
                pos++;
            } else if (opcode >= 0x28 && opcode <= 0x3E) {
                // memory load/store (alignment and offset as LEBs)
                while (pos < func.offset + func.size && (Data[pos] & 0x80)) pos++;
                pos++;
                while (pos < func.offset + func.size && (Data[pos] & 0x80)) pos++;
                pos++;
            } else if (opcode == 0x3F || opcode == 0x40) {
                // memory.size (0x3F) or memory.grow (0x40) have a reserved byte (0x00)
                if (pos < func.offset + func.size) pos++;
            } else if (opcode == 0x02 || opcode == 0x03) {
                // block (0x02) or loop (0x03) have a block type byte, then nested instructions until end.
                if (pos < func.offset + func.size) pos++; 
                // (Skipping nested block parsing for simplicity, stop when the matching end is encountered in main loop)
            }
            // (Other opcodes either have no immediates or are handled implicitly by the above cases)
        }
        if (instr_positions.size() > 1) {
            // Pick a random instruction (not the final END) to mutate.
            size_t instr_pos = instr_positions[rng() % (instr_positions.size() - 1)];
            uint8_t old_op = Data[instr_pos];
            uint8_t new_op = old_op;
            // Choose a replacement opcode. Try to pick one with a similar type signature to maintain validity.
            if ((old_op >= 0x6A && old_op <= 0x75) || (old_op >= 0x7C && old_op <= 0x87)) {
                // If it's an integer arithmetic/bit opcode (i32:* or i64:* range), swap within that category.
                static const uint8_t i32_ops[] = {0x6A,0x6B,0x6C,0x6D,0x6E,0x6F,0x70,0x71,0x72,0x73,0x74,0x75}; // i32 add/sub/mul/.../rotr
                static const uint8_t i64_ops[] = {0x7C,0x7D,0x7E,0x7F,0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87}; // i64 add/sub/...
                if (old_op >= 0x6A && old_op <= 0x75) {
                    new_op = i32_ops[rng() % (sizeof(i32_ops)/sizeof(i32_ops[0]))];
                } else {
                    new_op = i64_ops[rng() % (sizeof(i64_ops)/sizeof(i64_ops[0]))];
                }
            } else if (old_op == 0x41 || old_op == 0x42) {
                // If it's an integer constant, change it to the other integer const or a float const.
                new_op = (old_op == 0x41 ? 0x42 : 0x41); // swap i32.const <-> i64.const (just as an example mutation)
            } else {
                // Default: replace with a harmless `nop` (0x01) which preserves stack balance.
                new_op = 0x01;
            }
            Data[instr_pos] = new_op;
        }
        break;
    }
    case MUT_CHANGE_CONST: {
        // **Constant alteration**: find a numeric constant instruction and tweak its immediate value.
        if (!functions.empty()) {
            const FuncBody &func = functions[rng() % functions.size()];
            // Linear scan for a const opcode in this function body
            for (size_t pos = func.offset; pos < func.offset + func.size; ++pos) {
                uint8_t op = Data[pos];
                if (op == 0x41 || op == 0x42 || op == 0x43 || op == 0x44) {
                    // Found an i32.const (0x41), i64.const (0x42), f32.const (0x43), or f64.const (0x44).
                    if (op == 0x41 || op == 0x42) {
                        // Flip a bit in the LEB immediate (this will change the integer value).
                        size_t immPos = pos + 1;
                        if (immPos < func.offset + func.size) {
                            Data[immPos] ^= 1u << (rng() % 7);  // flip a random bit in one byte of LEB
                        }
                    } else if (op == 0x43) {
                        // F32: flip one random bit of the 32-bit IEEE754 representation.
                        if (pos + 4 < func.offset + func.size) {
                            uint32_t *fpBits = reinterpret_cast<uint32_t*>(Data + pos + 1);
                            *fpBits ^= 1u << (rng() % 32);
                        }
                    } else if (op == 0x44) {
                        // F64: flip a random bit of the 64-bit representation.
                        if (pos + 8 < func.offset + func.size) {
                            uint64_t *dpBits = reinterpret_cast<uint64_t*>(Data + pos + 1);
                            *dpBits ^= 1ull << (rng() % 64);
                        }
                    }
                    break; // mutate the first constant we find
                }
            }
        }
        break;
    }
    case MUT_CHANGE_SECTION: {
        // **Section-level mutation**: modify non-code sections in a safe way.
        if (dataSec) {
            // e.g. Flip a byte in the Data section (which holds initial memory bytes).
            size_t byte_offset = dataSec->offset + (rng() % dataSec->size);
            if (byte_offset < Size) {
                Data[byte_offset] ^= 0xFF;  // invert the byte
            }
        } else if (globalSec) {
            // e.g. Modify a global section's initial expression slightly.
            // For simplicity, flip a byte somewhere in the global section content.
            size_t byte_offset = globalSec->offset + (rng() % globalSec->size);
            if (byte_offset < Size) {
                Data[byte_offset] ^= 0x01;
            }
        } else if (typeSec) {
            // e.g. If no data/global, tweak the type section: flip a bit in the type section content.
            size_t byte_offset = typeSec->offset + (rng() % typeSec->size);
            Data[byte_offset] ^= 0x01;
        } else {
            // If none of the above sections exist, add a dummy custom section at end if space allows.
            const char *name = "fuzz";
            uint32_t nameLen = (uint32_t)strlen(name);
            uint32_t newSecSize = 1 + nameLen; // name length LEB + name bytes (no payload)
            uint32_t totalNewBytes = 1 +                // section ID (0 for custom)
                                     (nameLen < 128 ? 1 : 2) + // size LEB (approximate)
                                     newSecSize;
            if (Size + totalNewBytes <= MaxSize) {
                // Append a new custom section with name "fuzz" and no extra content.
                Data[Size] = 0x00; // custom section ID
                // Write section size LEB (name length + 1 for the length field itself).
                uint8_t sizeBytes[5];
                size_t sizeByteCount = 0;
                uint32_t payloadLen = newSecSize;
                do {
                    uint8_t byte = payloadLen & 0x7F;
                    payloadLen >>= 7;
                    if (payloadLen != 0) byte |= 0x80;
                    sizeBytes[sizeByteCount++] = byte;
                } while (payloadLen != 0 && sizeByteCount < 5);
                // Copy size LEB
                memcpy(Data + Size + 1, sizeBytes, sizeByteCount);
                // Write name length and name
                Data[Size + 1 + sizeByteCount] = (uint8_t)nameLen;
                memcpy(Data + Size + 2 + sizeByteCount, name, nameLen);
                Size += (1 + sizeByteCount + newSecSize);
            }
        }
        break;
    }
    default:
        break;
    }

    size_t newSize = std::min(Size, MaxSize);
    return newSize;
}
