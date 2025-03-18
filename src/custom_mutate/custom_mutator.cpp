#include <binaryen/src/wasm.h>
#include <binaryen/src/wasm-binary.h>
#include <binaryen/src/wasm-builder.h>
#include <binaryen/src/wasm-validator.h>
#include <random>
#include <vector>
#include <algorithm>
#include <cstring>
#include <iostream>
#include <limits>

using namespace wasm;

// Define Op as an alias for uint32_t.
using Op = uint32_t;


// Provide inline definitions for opcodes used in candidate lists.
// Arithmetic (i32)
inline Op BinaryenI32Add()    { return 0x6A; }
inline Op BinaryenI32Sub()    { return 0x6B; }
inline Op BinaryenI32Mul()    { return 0x6C; }
inline Op BinaryenI32DivS()   { return 0x6D; }
inline Op BinaryenI32DivU()   { return 0x6E; }
inline Op BinaryenI32And()    { return 0x71; }
inline Op BinaryenI32Or()     { return 0x72; }
inline Op BinaryenI32Xor()    { return 0x73; }

// Arithmetic (i64)
inline Op BinaryenI64Add()    { return 0x7C; }
inline Op BinaryenI64Sub()    { return 0x7D; }
inline Op BinaryenI64Mul()    { return 0x7E; }

// Floating-point (f32)
inline Op BinaryenF32Add()    { return 0x92; }
inline Op BinaryenF32Sub()    { return 0x93; }
inline Op BinaryenF32Mul()    { return 0x94; }
inline Op BinaryenF32Div()    { return 0x95; }

// Floating-point (f64)
inline Op BinaryenF64Add()    { return 0xA0; }
inline Op BinaryenF64Sub()    { return 0xA1; }
inline Op BinaryenF64Mul()    { return 0xA2; }
inline Op BinaryenF64Div()    { return 0xA3; }

// Control opcodes
inline Op BinaryenBrIf()      { return 0x0D; }
inline Op BinaryenBr()        { return 0x0C; }
inline Op BinaryenNop()       { return 0x01; }
inline Op BinaryenIf()        { return 0x04; }
inline Op BinaryenI32Eqz() { return 0x45; }

// Local variable opcodes
inline Op BinaryenLocalGet()  { return 0x20; }
inline Op BinaryenLocalSet()  { return 0x21; }
inline Op BinaryenLocalTee()  { return 0x22; }

// Global variable opcodes
inline Op BinaryenGlobalGet() { return 0x23; }
inline Op BinaryenGlobalSet() { return 0x24; }

// Call opcodes
inline Op BinaryenCallFunction()  { return 0x10; }
inline Op BinaryenCallIndirect()  { return 0x11; }
inline Op BinaryenCallRef()       { return 0x14; }

// Memory load opcodes
inline Op BinaryenI32Load()         { return 0x28; }
inline Op BinaryenI32LoadMem8S()    { return 0x2C; }
inline Op BinaryenI32LoadMem8U()    { return 0x2D; }
inline Op BinaryenI32LoadMem16S()   { return 0x2E; }
inline Op BinaryenI32LoadMem16U()   { return 0x2F; }
inline Op BinaryenI64Load()         { return 0x29; }

// Memory store opcodes
inline Op BinaryenI32Store()        { return 0x36; }
inline Op BinaryenI64Store()        { return 0x37; }

// Miscellaneous memory opcodes
inline Op BinaryenMemoryGrow()      { return 0x40; }
inline Op BinaryenMemorySize()      { return 0x3F; }

// SIMD opcodes
inline Op BinaryenS128Load()        { return 0xfd00; }
inline Op BinaryenS128Load8Lane()   { return 0xfd54; }
inline Op BinaryenS128Load16Lane()  { return 0xfd55; }
inline Op BinaryenS128Load32Lane()  { return 0xfd56; }

// Atomic opcodes
inline Op BinaryenI32AtomicLoad()   { return 0xfe10; }
inline Op BinaryenI32AtomicLoad8U() { return 0xfe12; }
inline Op BinaryenI32AtomicLoad16U(){ return 0xfe13; }

// GC opcodes
inline Op BinaryenStructNew()       { return 0xfb00; }
inline Op BinaryenStructNewDefault(){ return 0xfb01; }

//-----------------------------------------------------------------------------
// Parse a WASM module from binary data using Binaryen's API.
Module* parseWasmModuleFromBinary(const uint8_t* data, size_t size) {
    Module* module = new Module();
    try {
      std::vector<char> input(data, data + size);
      WasmBinaryReader reader(*module, input.data(), input.size(), false);
      reader.read();
    } catch (std::exception& e) {
      std::cerr << "Module parse error: " << e.what() << "\n";
      delete module;
      return nullptr;
    }
    return module;
  }

//-----------------------------------------------------------------------------
// Walk the AST in postorder and collect pointers to all expressions.
std::vector<Expression*> collectExpressions(Expression* root) {
    std::vector<Expression*> result;
    struct Collector : public PostWalker<Collector> {
      std::vector<Expression*>& result;
      Collector(std::vector<Expression*>& r) : result(r) {}
      void visitExpression(Expression* curr) { result.push_back(curr); }
    };
    Collector collector(result);
    if (root) {
      collector.walk(root);
    }
    return result;
  }

//-----------------------------------------------------------------------------
// Return a replacement opcode for a given opcode based on its category.
// For demonstration, we cover several representative categories.
// In a complete implementation, candidate lists for every category defined
// by the FOREACH_OPCODE macros should be used.
Op getReplacementForOp(Op opcode, std::mt19937& rng) {
  // ----- Arithmetic (i32) opcodes -----
  if (opcode == BinaryenI32Add()) {
    std::vector<Op> candidates = { BinaryenI32Sub(), BinaryenI32Mul(),
                                   BinaryenI32DivS(), BinaryenI32DivU(),
                                   BinaryenI32And(), BinaryenI32Or(), BinaryenI32Xor() };
    std::uniform_int_distribution<size_t> dist(0, candidates.size()-1);
    return candidates[dist(rng)];
  } else if (opcode == BinaryenI32Sub()) {
    std::vector<Op> candidates = { BinaryenI32Add(), BinaryenI32Mul() };
    return candidates[rng() % candidates.size()];
  }
  // ----- Arithmetic (i64) opcodes -----
  if (opcode == BinaryenI64Add()) {
    std::vector<Op> candidates = { BinaryenI64Sub(), BinaryenI64Mul() };
    return candidates[rng() % candidates.size()];
  } else if (opcode == BinaryenI64Sub()) {
    std::vector<Op> candidates = { BinaryenI64Add(), BinaryenI64Mul() };
    return candidates[rng() % candidates.size()];
  }
  // ----- Floating-point opcodes (f32) -----
  if (opcode == BinaryenF32Add()) {
    std::vector<Op> candidates = { BinaryenF32Sub(), BinaryenF32Mul(), BinaryenF32Div() };
    return candidates[rng() % candidates.size()];
  } else if (opcode == BinaryenF32Sub()) {
    std::vector<Op> candidates = { BinaryenF32Add(), BinaryenF32Mul(), BinaryenF32Div() };
    return candidates[rng() % candidates.size()];
  }
  // ----- Floating-point opcodes (f64) -----
  if (opcode == BinaryenF64Add()) {
    std::vector<Op> candidates = { BinaryenF64Sub(), BinaryenF64Mul(), BinaryenF64Div() };
    return candidates[rng() % candidates.size()];
  } else if (opcode == BinaryenF64Sub()) {
    std::vector<Op> candidates = { BinaryenF64Add(), BinaryenF64Mul(), BinaryenF64Div() };
    return candidates[rng() % candidates.size()];
  }
  // ----- Control opcodes -----
  if (opcode == BinaryenBrIf()) {
    std::vector<Op> candidates = { BinaryenBr(), BinaryenNop() };
    return candidates[rng() % candidates.size()];
  } else if (opcode == BinaryenIf()) {
    // Replace an if with a Nop or possibly a block containing the then-branch.
    std::vector<Op> candidates = { BinaryenNop() };
    return candidates[rng() % candidates.size()];
  }
  // ----- Local variable opcodes -----
  if (opcode == BinaryenLocalGet()) {
    std::vector<Op> candidates = { BinaryenLocalSet(), BinaryenLocalTee() };
    return candidates[rng() % candidates.size()];
  } else if (opcode == BinaryenLocalSet()) {
    std::vector<Op> candidates = { BinaryenLocalGet(), BinaryenLocalTee() };
    return candidates[rng() % candidates.size()];
  }
  // ----- Global variable opcodes -----
  if (opcode == BinaryenGlobalGet()) {
    std::vector<Op> candidates = { BinaryenGlobalSet() };
    return candidates[rng() % candidates.size()];
  } else if (opcode == BinaryenGlobalSet()) {
    std::vector<Op> candidates = { BinaryenGlobalGet() };
    return candidates[rng() % candidates.size()];
  }
  // ----- Call opcodes -----
  if (opcode == BinaryenCallFunction()) {
    std::vector<Op> candidates = { BinaryenCallIndirect(), BinaryenCallRef() };
    return candidates[rng() % candidates.size()];
  }
  // ----- Memory load opcodes -----
  if (opcode == BinaryenI32Load()) {
    std::vector<Op> candidates = { BinaryenI32LoadMem8S(), BinaryenI32LoadMem8U(),
                                   BinaryenI32LoadMem16S(), BinaryenI32LoadMem16U() };
    return candidates[rng() % candidates.size()];
  } else if (opcode == BinaryenI64Load()) {
    std::vector<Op> candidates = { /* Add i64.load variants if available */ };
    if (!candidates.empty()) return candidates[rng() % candidates.size()];
  }
  // ----- Memory store opcodes -----
  if (opcode == BinaryenI32Store()) {
    std::vector<Op> candidates = { /* Add i32.store variants if available */ };
    if (!candidates.empty()) return candidates[rng() % candidates.size()];
  } else if (opcode == BinaryenI64Store()) {
    std::vector<Op> candidates = { /* Add i64.store variants if available */ };
    if (!candidates.empty()) return candidates[rng() % candidates.size()];
  }
  // ----- Miscellaneous memory opcodes -----
  if (opcode == BinaryenMemoryGrow()) {
    std::vector<Op> candidates = { BinaryenMemorySize() };
    return candidates[rng() % candidates.size()];
  }
  // ----- SIMD opcodes -----
  if (opcode == BinaryenS128Load()) {
    std::vector<Op> candidates = { BinaryenS128Load8Lane(), BinaryenS128Load16Lane(), BinaryenS128Load32Lane() };
    return candidates[rng() % candidates.size()];
  }
  // ----- Atomic opcodes -----
  if (opcode == BinaryenI32AtomicLoad()) {
    std::vector<Op> candidates = { BinaryenI32AtomicLoad8U(), BinaryenI32AtomicLoad16U() };
    return candidates[rng() % candidates.size()];
  }
  // ----- GC opcodes -----
  if (opcode == BinaryenStructNew()) {
    std::vector<Op> candidates = { BinaryenStructNewDefault() };
    return candidates[rng() % candidates.size()];
  }
  // If no replacement candidate is defined for this opcode category, return the original.
  return opcode;
}

//-----------------------------------------------------------------------------
// Constant Mutation: For every constant expression (i32, i64, f32, f64),
// randomly flip a bit or inject an extreme value.
void mutateConstantExpressions(Module* module, std::mt19937& rng) {
    for (auto& funcPtr : module->functions) {
      Function* func = funcPtr.get();
      std::vector<Expression*> exprs = collectExpressions(func->body);
      for (auto* expr : exprs) {
        if (auto* c = expr->dynCast<Const>()) {
          int choice = rng() % 2; // 0: bit flip, 1: extreme value injection
          if (c->type == Type::i32) {
            if (choice == 0) {
              int32_t oldVal = c->value.geti32();
              int bit = rng() % 32;
              int32_t newVal = oldVal ^ (1 << bit);
              c->value = Literal(newVal);
            } else {
              std::vector<int32_t> candidates = { 0, -1,
                std::numeric_limits<int32_t>::max(), std::numeric_limits<int32_t>::min() };
              c->value = Literal(candidates[rng() % candidates.size()]);
            }
          } else if (c->type == Type::i64) {
            if (choice == 0) {
              int64_t oldVal = c->value.geti64();
              int bit = rng() % 64;
              int64_t newVal = oldVal ^ (1LL << bit);
              c->value = Literal(newVal);
            } else {
              std::vector<int64_t> candidates = { 0LL, -1LL,
                std::numeric_limits<int64_t>::max(), std::numeric_limits<int64_t>::min() };
              c->value = Literal(candidates[rng() % candidates.size()]);
            }
          } else if (c->type == Type::f32) {
            if (choice == 0) {
              float oldVal = c->value.getf32();
              uint32_t bits;
              memcpy(&bits, &oldVal, sizeof(bits));
              int bit = rng() % 32;
              bits ^= (1u << bit);
              float newVal;
              memcpy(&newVal, &bits, sizeof(newVal));
              c->value = Literal(newVal);
            } else {
              std::vector<float> candidates = { 0.0f, -0.0f,
                std::numeric_limits<float>::infinity(), -std::numeric_limits<float>::infinity(),
                std::numeric_limits<float>::quiet_NaN() };
              c->value = Literal(candidates[rng() % candidates.size()]);
            }
          } else if (c->type == Type::f64) {
            if (choice == 0) {
              double oldVal = c->value.getf64();
              uint64_t bits;
              memcpy(&bits, &oldVal, sizeof(bits));
              int bit = rng() % 64;
              bits ^= (1ULL << bit);
              double newVal;
              memcpy(&newVal, &bits, sizeof(newVal));
              c->value = Literal(newVal);
            } else {
              std::vector<double> candidates = { 0.0, -0.0,
                std::numeric_limits<double>::infinity(), -std::numeric_limits<double>::infinity(),
                std::numeric_limits<double>::quiet_NaN() };
              c->value = Literal(candidates[rng() % candidates.size()]);
            }
          }
        }
      }
    }
  }

//-----------------------------------------------------------------------------
// Section Mutation: Modify the module's sections by either adding, cloning, or removing functions.
// In a full implementation, global and export sections could also be mutated.
  void mutateSection(Module* module, std::mt19937& rng) {
    int option = rng() % 3;
    if (option == 0) {
      // Add a new dummy function.
      Builder builder(*module);
      Function* newFunc = new Function();
      newFunc->name = Name("fuzz_dummy");
      newFunc->type = HeapType::none;
      Expression* constExpr = builder.makeConst(Literal(int32_t(0)));
      Expression* dropExpr = builder.makeDrop(constExpr);
      newFunc->body = dropExpr;
      module->addFunction(newFunc);
    } else if (option == 1) {
      // Clone a random function.
      if (!module->functions.empty()) {
        size_t idx = rng() % module->functions.size();
        Function* orig = module->functions[idx].get();
        Function* clone = new Function(*orig);
        // Concatenate the original name with "_clone" to form a new name.
        clone->name = Name(std::string(orig->name.str) + "_clone");
        module->addFunction(clone);
      }
    } else {
      // Remove the last function if possible.
      if (!module->functions.empty()) {
        std::string name = std::string(module->functions.back()->name.str);
        module->removeFunction(name);
      }
    }
  }

//-----------------------------------------------------------------------------
// Semantic Mutation: Insert dead code into a function's body.
// For example, insert an if(false){...} block that preserves semantics.
void mutateSemantic(Module* module, std::mt19937& rng) {
    if (!module->functions.empty()) {
      // Use .get() to obtain Function* from unique_ptr.
      Function* func = module->functions[rng() % module->functions.size()].get();
      Builder builder(*module);
      // Create an if-block with condition "false" (i32 0).
      Expression* falseConst = builder.makeConst(Literal(int32_t(0)));
      std::vector<Expression*> ifList;
      ifList.push_back(builder.makeNop());
      Expression* ifBlock = builder.makeBlock(ifList);
      Expression* ifExpr = builder.makeIf(falseConst, ifBlock);
      // If the function body is a Block, insert the if-block.
      if (auto* block = func->body->dynCast<Block>()) {
        // ArenaVector may not support insert(), so use push_back() instead.
        block->list.push_back(ifExpr);
      } else {
        func->body = builder.makeBlock({ func->body, ifExpr });
      }
    }
  }

//-----------------------------------------------------------------------------
// Control-Flow Mutation: Modify branch conditions in control expressions.
// For example, either invert the branch condition using i32.eqz or remove the condition.
void mutateControlFlow(Module* module, std::mt19937& rng) {
    for (auto& funcPtr : module->functions) {
      Function* func = funcPtr.get();
      std::vector<Expression*> exprs = collectExpressions(func->body);
      for (auto* expr : exprs) {
        // In Binaryen, conditional branches are represented by Break with a condition.
        if (auto* br = expr->dynCast<Break>()) {
          if (br->condition) {
            int option = rng() % 2; // 0: invert condition, 1: remove condition
            if (option == 0) {
              Expression* oldCond = br->condition;
              // Expression* newCond = Builder(*module).makeUnary(BinaryenI32Eqz(), oldCond);
              Expression* newCond = Builder(*module).makeUnary(static_cast<UnaryOp>(BinaryenI32Eqz()), oldCond);
              br->condition = newCond;
            } else {
              br->condition = Builder(*module).makeNop();
            }
            return; // Apply one control-flow mutation per call.
          }
        }
      }
    }
  }

//-----------------------------------------------------------------------------
// Vulnerability Injection: Modify memory access offsets to huge values,
// and inject an invalid type index in call_indirect if possible.
// 5. Vulnerability Injection: call_indirect의 target은 Expression*이어야 하므로, 상수 표현식을 생성합니다.
void injectVulnerability(Module* module, std::mt19937& rng) {
    for (auto& funcPtr : module->functions) {
      Function* func = funcPtr.get();
      std::vector<Expression*> exprs = collectExpressions(func->body);
      for (auto* expr : exprs) {
        if (auto* load = expr->dynCast<Load>()) {
          load->offset = 0xFFFFFFF0;
        } else if (auto* store = expr->dynCast<Store>()) {
          store->offset = 0xFFFFFFF0;
        }
        // For CallIndirect, inject an invalid target by creating a constant 0.
        else if (auto* callIndirect = expr->dynCast<CallIndirect>()) {
          callIndirect->target = Builder(*module).makeConst(Literal((uint32_t)0));
        }
      }
    }
  }

//-----------------------------------------------------------------------------
// Instruction Mutation: Walk through all expressions in every function
// and if the expression is a Binary (or similar) operator, replace its opcode
// with one drawn from a candidate list based on its category.
// For commutative operations, optionally swap operands.
// Additional cases for Call, CallIndirect, Memory Load/Store, Select, Drop,
// and Block expressions are added.
void mutateInstructions(Module* module, std::mt19937& rng) {
    // Iterate over every function in the module.
    for (auto& funcPtr : module->functions) {
      Function* func = funcPtr.get();
      // Collect all expressions in the function body.
      std::vector<Expression*> exprs = collectExpressions(func->body);
      // Process each expression.
      for (auto* expr : exprs) {
        // ----- Binary Expressions -----
        if (auto* binary = expr->dynCast<Binary>()) {
          // Replace opcode using candidate list based on its category.
          Op newOp = getReplacementForOp(binary->op, rng);
          // Determine if the operation is commutative.
          bool commutative = false;
          if (binary->op == BinaryenI32Add() || binary->op == BinaryenI32Mul() ||
              binary->op == BinaryenI32And() || binary->op == BinaryenI32Or()  ||
              binary->op == BinaryenI32Xor() ||
              binary->op == BinaryenF32Add() || binary->op == BinaryenF32Mul() ||
              binary->op == BinaryenF64Add() || binary->op == BinaryenF64Mul()) {
            commutative = true;
          }
          // Randomly swap operands for commutative operations.
          if (commutative && (rng() % 2 == 0)) {
            std::swap(binary->left, binary->right);
          }
          // Cast newOp (Op) to BinaryOp.
          binary->op = static_cast<BinaryOp>(newOp);
        }
        // ----- Unary Expressions -----
        else if (auto* unary = expr->dynCast<Unary>()) {
            if (unary->op == static_cast<UnaryOp>(BinaryenI32Eqz())) {
              std::vector<Op> candidates = { BinaryenNop() };
              unary->op = static_cast<UnaryOp>(candidates[rng() % candidates.size()]);
            }
        }
        // ----- Call Expressions -----
        else if (auto* call = expr->dynCast<Call>()) {
            if (!module->functions.empty()) {
              std::vector<std::string> candidateTargets;
              for (auto& fPtr : module->functions) {
                Function* f = fPtr.get();
                if (f->name.str != call->target.str) {
                  candidateTargets.push_back(std::string(f->name.str));
                }
              }
              if (!candidateTargets.empty()) {
                std::uniform_int_distribution<size_t> dist(0, candidateTargets.size()-1);
                call->target = Name(candidateTargets[dist(rng)]);
              }
            }
          }
        // ----- CallIndirect Expressions -----
        else if (auto* callIndirect = expr->dynCast<CallIndirect>()) {
            // Instead of using module->types (which is unavailable), choose a fixed value.
            callIndirect->target = Builder(*module).makeConst(Literal((uint32_t)0));
          }
        // ----- Memory Load Expressions -----
        else if (auto* load = expr->dynCast<Load>()) {
          // Adjust the 'bytes' field to a candidate value and update alignment.
          std::vector<unsigned> candidateBytes = { 1, 2, 4, 8 };
          load->bytes = candidateBytes[rng() % candidateBytes.size()];
          load->align = load->bytes;
        }
        // ----- Memory Store Expressions -----
        else if (auto* store = expr->dynCast<Store>()) {
          // Adjust the 'bytes' field for store expressions similarly.
          std::vector<unsigned> candidateBytes = { 1, 2, 4, 8 };
          store->bytes = candidateBytes[rng() % candidateBytes.size()];
          store->align = store->bytes;
        }
        // ----- Select Expressions -----
        else if (auto* sel = expr->dynCast<Select>()) {
            if (rng() % 2 == 0) {
              std::swap(sel->ifTrue, sel->ifFalse);
            } else {
              if (sel->condition && sel->condition->type == Type::i32) {
                Expression* newCond = Builder(*module).makeUnary(static_cast<UnaryOp>(BinaryenI32Eqz()), sel->condition);
                sel->condition = newCond;
              }
            }
        }
        // ----- Drop Expressions -----
        else if (auto* drop = expr->dynCast<Drop>()) {
          // Optionally, wrap the drop's value with a block that inserts a Nop.
          if (rng() % 2 == 0) {
            Expression* nopExpr = Builder(*module).makeNop();
            drop->value = Builder(*module).makeBlock({ nopExpr, drop->value });
          }
        }
        // ----- Block Expressions -----
        else if (auto* block = expr->dynCast<Block>()) {
            if (!block->list.empty() && (rng() % 2 == 0)) {
              size_t idx = rng() % block->list.size();
              Expression* duplicate = block->list[idx]; // shallow copy; deep clone is preferable
              // ArenaVector may not support insert; use push_back to duplicate the statement.
              block->list.push_back(duplicate);
            }
        }
        // Additional cases for other expression types (e.g. Loop, If, etc.) can be added here.
      }
    }
  }
  

//-----------------------------------------------------------------------------
// Main custom mutator function for libFuzzer.
// This function parses the input WASM binary using Binaryen, randomly selects one
// of six mutation strategies (instruction, constant, section, semantic, control-flow,
// vulnerability injection), applies it, validates the mutated module, and then
// serializes it back to binary.
extern "C" size_t LLVMFuzzerCustomMutator(uint8_t* Data, size_t Size, size_t MaxSize, unsigned int Seed) {
    std::mt19937 rng(Seed);
    Module* module = parseWasmModuleFromBinary(Data, Size);
    if (!module) {
      static const uint8_t dummy_module[] = {
        0x00,0x61,0x73,0x6d, 0x01,0x00,0x00,0x00,
        0x01,0x04,0x01,0x60,0x00,0x00,
        0x03,0x02,0x01,0x00,
        0x0A,0x04,0x01, 0x02,0x00,0x0B
      };
      size_t dummySize = sizeof(dummy_module);
      if (dummySize <= MaxSize) {
        memcpy(Data, dummy_module, dummySize);
      }
      return dummySize;
    }
    
    int strat = rng() % 6;
    switch (strat) {
      case 0: mutateInstructions(module, rng); break;
      case 1: mutateConstantExpressions(module, rng); break;
      case 2: mutateSection(module, rng); break;
      case 3: mutateSemantic(module, rng); break;
      case 4: mutateControlFlow(module, rng); break;
      case 5: injectVulnerability(module, rng); break;
      default: break;
    }
    
    // Validate the mutated module using the static validate function.
    if (!WasmValidator().validate(*module)) {
      delete module;
      return Size; // Return original input if mutation is invalid.
    }
    
    // Serialize the mutated module back to binary.
    std::vector<char> output;
    WasmBinaryWriter writer(&module, output, false);
    writer.write();
    
    size_t outSize = output.size();
    size_t newSize = std::min(outSize, MaxSize);
    memcpy(Data, output.data(), newSize);
    
    delete module;
    return newSize;
  }
