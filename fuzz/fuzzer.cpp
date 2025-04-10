#include <iostream>
#include <locale>
#include <sstream>
#include <iomanip>
#include <inttypes.h>

#include <binaryen/src/wasm.h>
#include <binaryen/src/wasm-io.h>
#include <binaryen/src/wasm-binary.h>
#include <binaryen/src/wasm-builder.h>
#include <binaryen/src/wasm-validator.h>
#include <random>
#include <vector>
#include <algorithm>
#include <cstring>
#include <limits>

#if defined(WALRUS_GOOGLE_PERF)
#include <gperftools/profiler.h>
#endif

#include "Walrus.h"
#include "runtime/Engine.h"
#include "runtime/Store.h"
#include "runtime/Module.h"
#include "runtime/Instance.h"
#include "runtime/Function.h"
#include "runtime/Table.h"
#include "runtime/Memory.h"
#include "runtime/Global.h"
#include "runtime/Tag.h"
#include "runtime/Trap.h"
#include "runtime/DefinedFunctionTypes.h"
#include "parser/WASMParser.h"

#include "wabt/wast-lexer.h"
#include "wabt/wast-parser.h"
#include "wabt/binary-writer.h"
#include "string-view-lite/string_view.h"

#ifdef ENABLE_WASI
#include "wasi/WASI.h"
#endif

struct spectestseps : std::numpunct<char> {
    char do_thousands_sep() const { return '_'; }
    std::string do_grouping() const { return "\3"; }
};

struct ParseOptions {
    std::string exportToRun;
    std::vector<std::string> fileNames;

    // WASI options
    std::vector<std::string> wasi_envs;
    std::vector<std::pair<std::string, std::string>> wasi_dirs;
    int argsIndex = -1;
};

static uint32_t s_JITFlags = 0;

using namespace Walrus;

static void printI32(int32_t v)
{
    std::stringstream ss;
    std::locale slocale(std::locale(), new spectestseps);
    ss.imbue(slocale);
    ss << v;
    printf("%s : i32\n", ss.str().c_str());
}

static void printI64(int64_t v)
{
    std::stringstream ss;
    std::locale slocale(std::locale(), new spectestseps);
    ss.imbue(slocale);
    ss << v;
    printf("%s : i64\n", ss.str().c_str());
}

static std::string formatDecmialString(std::string s)
{
    while (s.find('.') != std::string::npos && s[s.length() - 1] == '0') {
        s.resize(s.length() - 1);
    }

    if (s.length() && s[s.length() - 1] == '.') {
        s.resize(s.length() - 1);
    }

    auto pos = s.find('.');
    if (pos != std::string::npos) {
        std::string out = s.substr(0, pos);
        out += ".";

        size_t cnt = 0;
        for (size_t i = pos + 1; i < s.length(); i++) {
            out += s[i];
            cnt++;
            if (cnt % 3 == 0 && i != s.length() - 1) {
                out += "_";
            }
        }

        s = out;
    }

    return s;
}

static void printF32(float v)
{
    std::stringstream ss;
    ss.imbue(std::locale(std::locale(), new spectestseps));
    ss.setf(std::ios_base::fixed);
    ss << std::setprecision(std::numeric_limits<float>::max_digits10);
    ss << v;
    printf("%s : f32\n", formatDecmialString(ss.str()).c_str());
}

static void printF64(double v)
{
    std::stringstream ss;
    ss.imbue(std::locale(std::locale(), new spectestseps));
    ss.setf(std::ios_base::fixed);
    ss << std::setprecision(std::numeric_limits<double>::max_digits10 - 1);
    ss << v;
    printf("%s : f64\n", formatDecmialString(ss.str()).c_str());
}

static Trap::TrapResult executeWASM(Store* store, const std::string& filename, const std::vector<uint8_t>& src, DefinedFunctionTypes& functionTypes,
                                    std::map<std::string, Instance*>* registeredInstanceMap = nullptr)
{
    auto parseResult = WASMParser::parseBinary(store, filename, src.data(), src.size(), s_JITFlags);
    if (!parseResult.second.empty()) {
        Trap::TrapResult tr;
        tr.exception = Exception::create(parseResult.second);
        return tr;
    }

    auto module = parseResult.first;
    const auto& importTypes = module->imports();

    ExternVector importValues;
    importValues.reserve(importTypes.size());
    /*
        (module ;; spectest host module(https://github.com/WebAssembly/spec/tree/main/interpreter)
          (global (export "global_i32") i32)
          (global (export "global_i64") i64)
          (global (export "global_f32") f32)
          (global (export "global_f64") f64)

          (table (export "table") 10 20 funcref)

          (memory (export "memory") 1 2)

          (func (export "print"))
          (func (export "print_i32") (param i32))
          (func (export "print_i64") (param i64))
          (func (export "print_f32") (param f32))
          (func (export "print_f64") (param f64))
          (func (export "print_i32_f32") (param i32 f32))
          (func (export "print_f64_f64") (param f64 f64))
        )
    */
    bool hasWasiImport = false;

    for (size_t i = 0; i < importTypes.size(); i++) {
        auto import = importTypes[i];
        if (import->moduleName() == "spectest") {
            if (import->fieldName() == "print") {
                auto ft = functionTypes[DefinedFunctionTypes::NONE];
                importValues.push_back(ImportedFunction::createImportedFunction(
                    store,
                    ft,
                    [](ExecutionState& state, Value* argv, Value* result, void* data) {
                    },
                    nullptr));
            } else if (import->fieldName() == "print_i32") {
                auto ft = functionTypes[DefinedFunctionTypes::I32R];
                importValues.push_back(ImportedFunction::createImportedFunction(
                    store,
                    ft,
                    [](ExecutionState& state, Value* argv, Value* result, void* data) {
                        printI32(argv[0].asI32());
                    },
                    nullptr));
            } else if (import->fieldName() == "print_i64") {
                auto ft = functionTypes[DefinedFunctionTypes::I64R];
                importValues.push_back(ImportedFunction::createImportedFunction(
                    store,
                    ft,
                    [](ExecutionState& state, Value* argv, Value* result, void* data) {
                        printI64(argv[0].asI64());
                    },
                    nullptr));
            } else if (import->fieldName() == "print_f32") {
                auto ft = functionTypes[DefinedFunctionTypes::F32R];
                importValues.push_back(ImportedFunction::createImportedFunction(
                    store,
                    ft,
                    [](ExecutionState& state, Value* argv, Value* result, void* data) {
                        printF32(argv[0].asF32());
                    },
                    nullptr));
            } else if (import->fieldName() == "print_f64") {
                auto ft = functionTypes[DefinedFunctionTypes::F64R];
                importValues.push_back(ImportedFunction::createImportedFunction(
                    store,
                    ft,
                    [](ExecutionState& state, Value* argv, Value* result, void* data) {
                        printF64(argv[0].asF64());
                    },
                    nullptr));
            } else if (import->fieldName() == "print_i32_f32") {
                auto ft = functionTypes[DefinedFunctionTypes::I32F32R];
                importValues.push_back(ImportedFunction::createImportedFunction(
                    store,
                    ft,
                    [](ExecutionState& state, Value* argv, Value* result, void* data) {
                        printI32(argv[0].asI32());
                        printF32(argv[1].asF32());
                    },
                    nullptr));
            } else if (import->fieldName() == "print_f64_f64") {
                auto ft = functionTypes[DefinedFunctionTypes::F64F64R];
                importValues.push_back(ImportedFunction::createImportedFunction(
                    store,
                    ft,
                    [](ExecutionState& state, Value* argv, Value* result, void* data) {
                        printF64(argv[0].asF64());
                        printF64(argv[1].asF64());
                    },
                    nullptr));
            } else if (import->fieldName() == "global_i32") {
                importValues.push_back(Global::createGlobal(store, Value(int32_t(666)), false));
            } else if (import->fieldName() == "global_i64") {
                importValues.push_back(Global::createGlobal(store, Value(int64_t(666)), false));
            } else if (import->fieldName() == "global_f32") {
                importValues.push_back(Global::createGlobal(store, Value(float(0x44268000)), false));
            } else if (import->fieldName() == "global_f64") {
                importValues.push_back(Global::createGlobal(store, Value(double(0x4084d00000000000)), false));
            } else if (import->fieldName() == "table") {
                importValues.push_back(Table::createTable(store, Value::Type::FuncRef, 10, 20));
            } else if (import->fieldName() == "memory") {
                importValues.push_back(Memory::createMemory(store, 1 * Memory::s_memoryPageSize, 2 * Memory::s_memoryPageSize, false));
            } else {
                // import wrong value for test
                auto ft = functionTypes[DefinedFunctionTypes::INVALID];
                importValues.push_back(ImportedFunction::createImportedFunction(
                    store,
                    ft,
                    [](ExecutionState& state, Value* argv, Value* result, void* data) {
                    },
                    nullptr));
            }
#ifdef ENABLE_WASI
        } else if (import->moduleName() == "wasi_snapshot_preview1") {
            WASI::WasiFuncInfo* wasiImportFunc = WASI::find(import->fieldName());
            if (wasiImportFunc) {
                FunctionType* ft = functionTypes[wasiImportFunc->functionType];
                if (ft->equals(import->functionType())) {
                    importValues.push_back(WasiFunction::createWasiFunction(
                        store,
                        ft,
                        wasiImportFunc->ptr));
                }
                hasWasiImport = true;
            }
#endif
        } else if (registeredInstanceMap) {
            auto iter = registeredInstanceMap->find(import->moduleName());
            if (iter != registeredInstanceMap->end()) {
                Instance* instance = iter->second;
                auto e = instance->resolveExportType(import->fieldName());
                if (e == nullptr) {
                    printf("Error: %s:%s module has not been found.\n", import->fieldName().c_str(), import->moduleName().c_str());
                    RELEASE_ASSERT_NOT_REACHED();
                }
                switch (e->exportType()) {
                case ExportType::Function:
                    importValues.push_back(instance->resolveExportFunction(import->fieldName()));
                    break;
                case ExportType::Tag:
                    importValues.push_back(instance->resolveExportTag(import->fieldName()));
                    break;
                case ExportType::Table:
                    importValues.push_back(instance->resolveExportTable(import->fieldName()));
                    break;
                case ExportType::Memory:
                    importValues.push_back(instance->resolveExportMemory(import->fieldName()));
                    break;
                case ExportType::Global:
                    importValues.push_back(instance->resolveExportGlobal(import->fieldName()));
                    break;
                default:
                    printf("Error: unsupported export type: %s\n", import->moduleName().c_str());
                    RELEASE_ASSERT_NOT_REACHED();
                    break;
                }
            }
        }
    }

    struct RunData {
        Module* module;
        ExternVector& importValues;
        bool hasWasiImport;
    } data = { module.value(), importValues, hasWasiImport };
    Walrus::Trap trap;
    return trap.run([](ExecutionState& state, void* d) {
        RunData* data = reinterpret_cast<RunData*>(d);
        Instance* instance = data->module->instantiate(state, data->importValues);

#ifdef ENABLE_WASI
        if (data->hasWasiImport) {
            for (auto&& exp : data->module->exports()) {
                if (exp->exportType() == ExportType::Function) {
                    if ("_start" != exp->name()) {
                        continue;
                    }

                    auto fn = instance->function(exp->itemIndex());
                    FunctionType* fnType = fn->asDefinedFunction()->moduleFunction()->functionType();

                    if (!fnType->param().empty()) {
                        printf("warning: function %s has params, but params are not supported\n", exp->name().c_str());
                        return;
                    }

                    if (!fnType->result().empty()) {
                        printf("warning: function %s has results, but results are not supported\n", exp->name().c_str());
                        return;
                    }


                    fn->call(state, nullptr, nullptr);
                }
            }
        }
#endif
    },
                    &data);
}

static bool endsWith(const std::string& str, const std::string& suffix)
{
    return str.size() >= suffix.size() && str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

static Walrus::Value toWalrusValue(wabt::Const& c)
{
    switch (c.type()) {
    case wabt::Type::I32:
        return Walrus::Value(static_cast<int32_t>(c.u32()));
    case wabt::Type::I64:
        return Walrus::Value(static_cast<int64_t>(c.u64()));
    case wabt::Type::F32: {
        if (c.is_expected_nan(0)) {
            return Walrus::Value(std::numeric_limits<float>::quiet_NaN());
        }
        float s;
        auto bits = c.f32_bits();
        memcpy(&s, &bits, sizeof(float));
        return Walrus::Value(s);
    }
    case wabt::Type::F64: {
        if (c.is_expected_nan(0)) {
            return Walrus::Value(std::numeric_limits<double>::quiet_NaN());
        }
        double s;
        auto bits = c.f64_bits();
        memcpy(&s, &bits, sizeof(double));
        return Walrus::Value(s);
    }
    case wabt::Type::V128: {
        Walrus::Vec128 v;
        v128 bits = c.vec128();
        memcpy((void*)&v, (void*)&bits, sizeof(v128));
        return Walrus::Value(v);
    }
    case wabt::Type::FuncRef: {
        if (c.ref_bits() == wabt::Const::kRefNullBits) {
            return Walrus::Value(Walrus::Value::FuncRef, Walrus::Value::Null);
        }
        // Add one similar to wabt interpreter.
        return Walrus::Value(Walrus::Value::FuncRef, c.ref_bits() + 1, Walrus::Value::Force);
    }
    case wabt::Type::ExternRef: {
        if (c.ref_bits() == wabt::Const::kRefNullBits) {
            return Walrus::Value(Walrus::Value::ExternRef, Walrus::Value::Null);
        }
        // Add one similar to wabt interpreter.
        return Walrus::Value(Walrus::Value::ExternRef, c.ref_bits() + 1, Walrus::Value::Force);
    }
    default:
        printf("Error: unknown value type during converting wabt::Const to wabt::Value\n");
        RELEASE_ASSERT_NOT_REACHED();
        return Walrus::Value();
    }
}

static bool isCanonicalNan(float val)
{
    uint32_t s;
    memcpy(&s, &val, sizeof(float));
    return s == 0x7fc00000U || s == 0xffc00000U;
}

static bool isCanonicalNan(double val)
{
    uint64_t s;
    memcpy(&s, &val, sizeof(double));
    return s == 0x7ff8000000000000ULL || s == 0xfff8000000000000ULL;
}

static bool isArithmeticNan(float val)
{
    uint32_t s;
    memcpy(&s, &val, sizeof(float));
    return (s & 0x7fc00000U) == 0x7fc00000U;
}

static bool isArithmeticNan(double val)
{
    uint64_t s;
    memcpy(&s, &val, sizeof(double));
    return (s & 0x7ff8000000000000ULL) == 0x7ff8000000000000ULL;
}

static bool equals(Walrus::Value& v, wabt::Const& c)
{
    if (c.type() == wabt::Type::I32 && v.type() == Walrus::Value::I32) {
        return v.asI32() == static_cast<int32_t>(c.u32());
    } else if (c.type() == wabt::Type::I64 && v.type() == Walrus::Value::I64) {
        return v.asI64() == static_cast<int64_t>(c.u64());
    } else if (c.type() == wabt::Type::F32 && v.type() == Walrus::Value::F32) {
        if (c.is_expected_nan(0)) {
            if (c.expected_nan() == wabt::ExpectedNan::Arithmetic) {
                return isArithmeticNan(v.asF32());
            } else {
                return isCanonicalNan(v.asF32());
            }
        }
        return c.f32_bits() == v.asF32Bits();
    } else if (c.type() == wabt::Type::F64 && v.type() == Walrus::Value::F64) {
        if (c.is_expected_nan(0)) {
            if (c.expected_nan() == wabt::ExpectedNan::Arithmetic) {
                return isArithmeticNan(v.asF64());
            } else {
                return isCanonicalNan(v.asF64());
            }
        }
        return c.f64_bits() == v.asF64Bits();
    } else if (c.type() == wabt::Type::V128 && v.type() == Walrus::Value::V128) {
        switch (c.lane_type()) {
        case wabt::Type::I8:
        case wabt::Type::I16:
        case wabt::Type::I32:
        case wabt::Type::I64:
            return memcmp(v.asV128Addr(), c.vec128().v, 16) == 0;
        case wabt::Type::F32: {
            bool result = true;
            for (int lane = 0; lane < c.lane_count(); ++lane) {
                if (c.is_expected_nan(lane)) {
                    float value = v.asV128().asF32(lane);
                    if (c.expected_nan(lane) == wabt::ExpectedNan::Arithmetic) {
                        result &= isArithmeticNan(value);
                    } else {
                        result &= isCanonicalNan(value);
                    }
                } else {
                    result &= (v.asV128().asF32Bits(lane) == c.v128_lane<uint32_t>(lane));
                }
            }
            return result;
        }
        case wabt::Type::F64: {
            bool result = true;
            for (int lane = 0; lane < c.lane_count(); ++lane) {
                if (c.is_expected_nan(lane)) {
                    double value = v.asV128().asF64(lane);
                    if (c.expected_nan(lane) == wabt::ExpectedNan::Arithmetic) {
                        result &= isArithmeticNan(value);
                    } else {
                        result &= isCanonicalNan(value);
                    }
                } else {
                    result &= (v.asV128().asF64Bits(lane) == c.v128_lane<uint64_t>(lane));
                }
            }
            return result;
        }
        default:
            return false;
        }

    } else if (c.type() == wabt::Type::ExternRef && v.type() == Walrus::Value::ExternRef) {
        // FIXME value of c.ref_bits() for RefNull
        wabt::Const constNull;
        constNull.set_null(c.type());
        if (c.ref_bits() == constNull.ref_bits()) {
            // check RefNull
            return v.isNull();
        }
        // Add one similar to wabt interpreter.
        return (c.ref_bits() + 1) == reinterpret_cast<uintptr_t>(v.asExternal());
    } else if (c.type() == wabt::Type::FuncRef && v.type() == Walrus::Value::FuncRef) {
        // FIXME value of c.ref_bits() for RefNull
        wabt::Const constNull;
        constNull.set_null(c.type());
        if (c.ref_bits() == constNull.ref_bits()) {
            // check RefNull
            return v.isNull();
        }
        // Add one similar to wabt interpreter.
        return (c.ref_bits() + 1) == reinterpret_cast<uintptr_t>(v.asFunction());
    }

    return false;
}

static void printConstVector(wabt::ConstVector& v)
{
    for (size_t i = 0; i < v.size(); i++) {
        auto c = v[i];
        switch (c.type()) {
        case wabt::Type::I32: {
            printf("%" PRIu32, c.u32());
            break;
        }
        case wabt::Type::I64: {
            printf("%" PRIu64, c.u64());
            break;
        }
        case wabt::Type::F32: {
            if (c.is_expected_nan(0)) {
                printf("nan");
                return;
            }
            float s;
            auto bits = c.f32_bits();
            memcpy(&s, &bits, sizeof(float));
            printf("%f", s);
            break;
        }
        case wabt::Type::F64: {
            if (c.is_expected_nan(0)) {
                printf("nan");
                return;
            }
            double s;
            auto bits = c.f64_bits();
            memcpy(&s, &bits, sizeof(double));
            printf("%lf", s);
            break;
        }
        case wabt::Type::V128: {
            char result[16 * 3];
            char* ptr = result;
            for (int i = 0; i < 16; i++) {
                uint8_t left = (c.vec128().u8(i) & 0xf0) >> 4;
                uint8_t right = c.vec128().u8(i) & 0x0f;
                ptr[0] = (left < 10) ? ('0' + left) : ('a' + (left - 10));
                ptr[1] = (right < 10) ? ('0' + right) : ('a' + (right - 10));
                ptr[2] = ':';
                ptr += 3;
            }
            ptr[-1] = '\0';
            printf("%s", result);
            break;
        }
        case wabt::Type::ExternRef: {
            // FIXME value of c.ref_bits() for RefNull
            wabt::Const constNull;
            constNull.set_null(c.type());
            if (c.ref_bits() == constNull.ref_bits()) {
                printf("ref.null");
                return;
            }
            break;
        }
        case wabt::Type::FuncRef: {
            // FIXME value of c.ref_bits() for RefNull
            wabt::Const constNull;
            constNull.set_null(c.type());
            if (c.ref_bits() == constNull.ref_bits()) {
                printf("ref.null");
                return;
            }
            break;
        }
        default: {
            printf("Error: unkown wabt::Const type\n");
            RELEASE_ASSERT_NOT_REACHED();
            break;
        }
        }
        if (i + 1 != v.size()) {
            printf(", ");
        }
    }
}

static void executeInvokeAction(wabt::InvokeAction* action, Walrus::Function* fn, wabt::ConstVector expectedResult,
                                const char* expectedException, bool expectUserException = false, bool either = false)
{
    if (fn->functionType()->param().size() != action->args.size()) {
        printf("Error: expected %zu parameter(s) but got %zu.\n", fn->functionType()->param().size(), action->args.size());
        RELEASE_ASSERT_NOT_REACHED();
    }
    Walrus::ValueVector args;
    for (auto& a : action->args) {
        args.push_back(toWalrusValue(a));
    }

    struct RunData {
        Walrus::Function* fn;
        wabt::ConstVector& expectedResult;
        Walrus::ValueVector& args;
        wabt::InvokeAction* action;
        bool either;
    } data = { fn, expectedResult, args, action, either };
    Walrus::Trap trap;
    auto trapResult = trap.run([](Walrus::ExecutionState& state, void* d) {
        RunData* data = reinterpret_cast<RunData*>(d);
        Walrus::ValueVector result;
        result.resize(data->fn->functionType()->result().size());
        data->fn->call(state, data->args.data(), result.data());
        if (data->expectedResult.size()) {
            int errorIndex = -1;

            if (data->either) {
                if (data->fn->functionType()->result().size() != 1) {
                    printf("Error: %s returned with %zu parameter(s) but expected 1", data->action->name.data(), data->fn->functionType()->result().size());
                    RELEASE_ASSERT_NOT_REACHED();
                }

                // compare result
                for (size_t i = 0; i < data->expectedResult.size(); i++) {
                    if (equals(result[0], data->expectedResult[i])) {
                        return;
                    }
                }

                errorIndex = 0;
            } else {
                if (data->fn->functionType()->result().size() != data->expectedResult.size()) {
                    printf("Error: %s returned with %zu parameter(s) but expected %zu", data->action->name.data(), data->fn->functionType()->result().size(), data->expectedResult.size());
                    RELEASE_ASSERT_NOT_REACHED();
                }

                // compare result
                for (size_t i = 0; i < result.size(); i++) {
                    if (!equals(result[i], data->expectedResult[i])) {
                        errorIndex = i;
                        break;
                    }
                }

                if (errorIndex == -1) {
                    return;
                }
            }

            printf("Assertion failed at %d: ", data->action->loc.line);
            printf("%s(", data->action->name.data());
            printConstVector(data->action->args);
            printf(") %sexpected ", data->either ? "any " : "");
            printConstVector(data->expectedResult);
            printf(", but got %s\n", ((std::string)result[errorIndex]).c_str());
            RELEASE_ASSERT_NOT_REACHED();
        }
    },
                               &data);
    if (expectedResult.size()) {
        if (trapResult.exception != nullptr) {
            printf("Error: %s\n", trapResult.exception->message().c_str());
            RELEASE_ASSERT_NOT_REACHED();
        }
    }
    if (expectedException) {
        if (trapResult.exception == nullptr) {
            printf("Missing exception: %s\n", expectedException);
            RELEASE_ASSERT_NOT_REACHED();
        }
        std::string& s = trapResult.exception->message();
        if (s.find(expectedException) != 0) {
            printf("Error: different error message than expected!\n");
            printf("Expected: %s\n", expectedException);
            printf("But got: %s\n", s.c_str());
            RELEASE_ASSERT_NOT_REACHED();
        }
        printf("invoke %s(", action->name.data());
        printConstVector(action->args);
        printf("), expect exception: %s (line: %d) : OK\n", expectedException, action->loc.line);
    } else if (expectUserException) {
        if (trapResult.exception->tag() == nullptr) {
            printf("Missing user exception: %s\n", action->name.data());
            RELEASE_ASSERT_NOT_REACHED();
        }
        printf("invoke %s(", action->name.data());
        printConstVector(action->args);
        printf(") expect user exception() (line: %d) : OK\n", action->loc.line);
    } else if (expectedResult.size()) {
        printf("invoke %s(", action->name.data());
        printConstVector(action->args);
        printf(") expect %svalue(", either ? "either " : "");
        printConstVector(expectedResult);
        printf(") (line: %d) : OK\n", action->loc.line);
    }
}

static std::unique_ptr<wabt::OutputBuffer> readModuleData(wabt::Module* module)
{
    wabt::MemoryStream stream;
    wabt::WriteBinaryOptions options;
    wabt::Features features;
    features.EnableAll();
    options.features = features;
    wabt::WriteBinaryModule(&stream, module, options);
    stream.Flush();
    return stream.ReleaseOutputBuffer();
}

static Instance* fetchInstance(wabt::Var& moduleVar, std::map<size_t, Instance*>& instanceMap,
                               std::map<std::string, Instance*>& registeredInstanceMap)
{
    if (moduleVar.is_index()) {
        return instanceMap[moduleVar.index()];
    }
    return registeredInstanceMap[moduleVar.name()];
}

static void executeWAST(Store* store, const std::string& filename, const std::vector<uint8_t>& src, DefinedFunctionTypes& functionTypes)
{
    wabt::Errors errors;
    auto lexer = wabt::WastLexer::CreateBufferLexer("test.wabt", src.data(), src.size(), &errors);
    ASSERT(lexer);

    std::unique_ptr<wabt::Script> script;
    wabt::Features features;
    features.EnableAll();
    wabt::WastParseOptions parse_wast_options(features);
    auto result = wabt::ParseWastScript(lexer.get(), &script, &errors, &parse_wast_options);
    if (!wabt::Succeeded(result)) {
        printf("Syntax error(s):\n");
        for (auto& e : errors) {
            printf("  %s\n", e.message.c_str());
        }
        printf("\n");
        RELEASE_ASSERT_NOT_REACHED();
    }

    std::map<size_t, Instance*> instanceMap;
    std::map<std::string, Instance*> registeredInstanceMap;
    size_t commandCount = 0;
    for (const std::unique_ptr<wabt::Command>& command : script->commands) {
        switch (command->type) {
        case wabt::CommandType::Module:
        case wabt::CommandType::ScriptModule: {
            auto* moduleCommand = static_cast<wabt::ModuleCommand*>(command.get());
            auto buf = readModuleData(&moduleCommand->module);
            auto trapResult = executeWASM(store, filename, buf->data, functionTypes, &registeredInstanceMap);
            if (trapResult.exception) {
                std::string& errorMessage = trapResult.exception->message();
                printf("Error: %s\n", errorMessage.c_str());
                RELEASE_ASSERT_NOT_REACHED();
            }
            instanceMap[commandCount] = store->getLastInstance();
            if (moduleCommand->module.name.size()) {
                registeredInstanceMap[moduleCommand->module.name] = store->getLastInstance();
            }
            break;
        }
        case wabt::CommandType::AssertReturn: {
            auto* assertReturn = static_cast<wabt::AssertReturnCommand*>(command.get());
            auto value = fetchInstance(assertReturn->action->module_var, instanceMap, registeredInstanceMap)->resolveExportType(assertReturn->action->name);
            if (value == nullptr) {
                printf("Undefined function: %s\n", assertReturn->action->name.c_str());
                RELEASE_ASSERT_NOT_REACHED();
            }
            if (assertReturn->action->type() == wabt::ActionType::Invoke) {
                auto action = static_cast<wabt::InvokeAction*>(assertReturn->action.get());
                auto fn = fetchInstance(action->module_var, instanceMap, registeredInstanceMap)->resolveExportFunction(action->name);
                executeInvokeAction(action, fn, assertReturn->expected->expected, nullptr, false, assertReturn->expected->type() == wabt::ExpectationType::Either);
            } else if (assertReturn->action->type() == wabt::ActionType::Get) {
                auto action = static_cast<wabt::GetAction*>(assertReturn->action.get());
                auto v = fetchInstance(action->module_var, instanceMap, registeredInstanceMap)->resolveExportGlobal(action->name)->value();
                if (!equals(v, assertReturn->expected->expected[0])) {
                    printf("Assert failed.\n");
                    RELEASE_ASSERT_NOT_REACHED();
                }
                printf("get %s", action->name.data());
                printf(" expect value(");
                printConstVector(assertReturn->expected->expected);
                printf(") (line: %d) : OK\n", action->loc.line);
            } else {
                printf("Not supported action type.\n");
                RELEASE_ASSERT_NOT_REACHED();
            }
            break;
        }
        case wabt::CommandType::AssertTrap: {
            auto* assertTrap = static_cast<wabt::AssertTrapCommand*>(command.get());
            auto value = fetchInstance(assertTrap->action->module_var, instanceMap, registeredInstanceMap)->resolveExportFunction(assertTrap->action->name);
            if (value == nullptr) {
                printf("Error: fetchInstance returned with nullptr.\n");
                RELEASE_ASSERT_NOT_REACHED();
            }
            if (assertTrap->action->type() == wabt::ActionType::Invoke) {
                auto action = static_cast<wabt::InvokeAction*>(assertTrap->action.get());
                auto fn = fetchInstance(action->module_var, instanceMap, registeredInstanceMap)->resolveExportFunction(action->name);
                executeInvokeAction(action, fn, wabt::ConstVector(), assertTrap->text.data());
            } else {
                ASSERT_NOT_REACHED();
            }
            break;
        }
        case wabt::CommandType::AssertException: {
            auto* assertException = static_cast<wabt::AssertExceptionCommand*>(command.get());
            auto value = fetchInstance(assertException->action->module_var, instanceMap, registeredInstanceMap)->resolveExportFunction(assertException->action->name);
            if (value == nullptr) {
                printf("Fetching instance failed (at wabt::CommandType::AssertException case)\n");
                RELEASE_ASSERT_NOT_REACHED();
            }
            if (assertException->action->type() == wabt::ActionType::Invoke) {
                auto action = static_cast<wabt::InvokeAction*>(assertException->action.get());
                auto fn = fetchInstance(action->module_var, instanceMap, registeredInstanceMap)->resolveExportFunction(action->name);
                executeInvokeAction(action, fn, wabt::ConstVector(), nullptr, true);
            } else {
                ASSERT_NOT_REACHED();
            }
            break;
        }
        case wabt::CommandType::AssertUninstantiable: {
            auto* assertModuleUninstantiable = static_cast<wabt::AssertModuleCommand<wabt::CommandType::AssertUninstantiable>*>(command.get());
            auto m = assertModuleUninstantiable->module.get();
            auto tsm = dynamic_cast<wabt::TextScriptModule*>(m);
            if (tsm == nullptr) {
                printf("Error at casting to wabt::TextScriptModule*.\n");
                RELEASE_ASSERT_NOT_REACHED();
            }
            auto buf = readModuleData(&tsm->module);
            auto trapResult = executeWASM(store, filename, buf->data, functionTypes, &registeredInstanceMap);
            RELEASE_ASSERT(trapResult.exception);
            std::string& s = trapResult.exception->message();
            if (s.find(assertModuleUninstantiable->text) != 0) {
                printf("Error: different error message than expected!\n");
                printf("Expected: %s\n", assertModuleUninstantiable->text.c_str());
                printf("But got: %s\n", s.c_str());
                RELEASE_ASSERT_NOT_REACHED();
            }
            printf("assertModuleUninstantiable (expect exception: %s(line: %d)) : OK\n", assertModuleUninstantiable->text.data(), assertModuleUninstantiable->module->location().line);
            break;
        }
        case wabt::CommandType::Register: {
            auto* registerCommand = static_cast<wabt::RegisterCommand*>(command.get());
            registeredInstanceMap[registerCommand->module_name] = fetchInstance(registerCommand->var, instanceMap, registeredInstanceMap);
            break;
        }
        case wabt::CommandType::Action: {
            auto* actionCommand = static_cast<wabt::ActionCommand*>(command.get());
            auto value = fetchInstance(actionCommand->action->module_var, instanceMap, registeredInstanceMap)->resolveExportFunction(actionCommand->action->name);
            if (value == nullptr) {
                printf("Fetching instance failed (at wabt::CommandType::Action case)");
                RELEASE_ASSERT_NOT_REACHED();
            }
            if (actionCommand->action->type() == wabt::ActionType::Invoke) {
                auto action = static_cast<wabt::InvokeAction*>(actionCommand->action.get());
                auto fn = fetchInstance(action->module_var, instanceMap, registeredInstanceMap)->resolveExportFunction(action->name);
                executeInvokeAction(action, fn, wabt::ConstVector(), nullptr);
            } else {
                ASSERT_NOT_REACHED();
            }
            break;
        }
        case wabt::CommandType::AssertInvalid: {
            auto* assertModuleInvalid = static_cast<wabt::AssertModuleCommand<wabt::CommandType::AssertInvalid>*>(command.get());
            auto m = assertModuleInvalid->module.get();
            auto tsm = dynamic_cast<wabt::TextScriptModule*>(m);
            auto dsm = dynamic_cast<wabt::BinaryScriptModule*>(m);
            if (!tsm && !dsm) {
                printf("Module is neither TextScriptModule nor BinaryScriptModule.\n");
                RELEASE_ASSERT_NOT_REACHED();
            }
            std::vector<uint8_t> buf;
            if (tsm) {
                buf = readModuleData(&tsm->module)->data;
            } else {
                buf = dsm->data;
            }
            auto trapResult = executeWASM(store, filename, buf, functionTypes);
            if (trapResult.exception == nullptr) {
                printf("Execute WASM returned nullptr (in wabt::CommandType::AssertInvalid case)\n");
                printf("Expected exception:%s\n", assertModuleInvalid->text.data());
                RELEASE_ASSERT_NOT_REACHED();
            }
            std::string& actual = trapResult.exception->message();
            printf("assertModuleInvalid (expect compile error: '%s', actual '%s'(line: %d)) : OK\n", assertModuleInvalid->text.data(), actual.data(), assertModuleInvalid->module->location().line);
            break;
        }
        case wabt::CommandType::AssertMalformed: {
            // we don't need to run invalid wat
            auto* assertMalformed = static_cast<wabt::AssertModuleCommand<wabt::CommandType::AssertMalformed>*>(command.get());
            break;
        }
        case wabt::CommandType::AssertUnlinkable: {
            auto* assertUnlinkable = static_cast<wabt::AssertUnlinkableCommand*>(command.get());
            auto m = assertUnlinkable->module.get();
            auto tsm = dynamic_cast<wabt::TextScriptModule*>(m);
            auto dsm = dynamic_cast<wabt::BinaryScriptModule*>(m);
            if (!tsm && !dsm) {
                printf("Both TextScriptModule* and BinaryScriptModule* castings failed (in wabt::CommandType::AssertUnlinkable case)\n");
                RELEASE_ASSERT_NOT_REACHED();
            }

            std::vector<uint8_t> buf;
            if (tsm) {
                buf = readModuleData(&tsm->module)->data;
            } else {
                buf = dsm->data;
            }
            auto trapResult = executeWASM(store, filename, buf, functionTypes);
            if (trapResult.exception == nullptr) {
                printf("Execute WASM returned nullptr (in wabt::CommandType::AssertUnlinkable case)\n");
                printf("Expected exception:%s\n", assertUnlinkable->text.data());
                RELEASE_ASSERT_NOT_REACHED();
            }
            break;
        }
        case wabt::CommandType::AssertExhaustion: {
            auto* assertExhaustion = static_cast<wabt::AssertExhaustionCommand*>(command.get());
            auto value = fetchInstance(assertExhaustion->action->module_var, instanceMap, registeredInstanceMap)->resolveExportFunction(assertExhaustion->action->name);
            if (value == nullptr) {
                printf("Fetching instance failed (at wabt::CommandType::AssertExhaustion case)\n");
                RELEASE_ASSERT_NOT_REACHED();
            }
            if (assertExhaustion->action->type() == wabt::ActionType::Invoke) {
                auto action = static_cast<wabt::InvokeAction*>(assertExhaustion->action.get());
                auto fn = fetchInstance(action->module_var, instanceMap, registeredInstanceMap)->resolveExportFunction(action->name);
                executeInvokeAction(action, fn, wabt::ConstVector(), assertExhaustion->text.data());
            } else {
                ASSERT_NOT_REACHED();
            }
            break;
        }
        default: {
            RELEASE_ASSERT_NOT_REACHED();
            break;
        }
        }

        commandCount++;
    }
}

static void runExports(Store* store, const std::string& filename, const std::vector<uint8_t>& src, std::string& exportToRun, DefinedFunctionTypes& functionTypes)
{
    auto parseResult = WASMParser::parseBinary(store, filename, src.data(), src.size(), s_JITFlags);
    if (!parseResult.second.empty()) {
        fprintf(stderr, "parse error: %s\n", parseResult.second.c_str());
        return;
    }

    auto module = parseResult.first;
    const auto& importTypes = module->imports();
    ExternVector importValues;
    importValues.reserve(importTypes.size());

    for (size_t i = 0; i < importTypes.size(); i++) {
#ifdef ENABLE_WASI
        auto import = importTypes[i];
        if (import->moduleName() == "wasi_snapshot_preview1") {
            Walrus::WASI::WasiFuncInfo* wasiImportFunc = WASI::find(import->fieldName());
            if (wasiImportFunc != nullptr) {
                FunctionType* ft = functionTypes[wasiImportFunc->functionType];
                if (ft->equals(import->functionType())) {
                    importValues.push_back(WasiFunction::createWasiFunction(
                        store,
                        ft,
                        wasiImportFunc->ptr));
                }
            }
        } else {
            fprintf(stderr, "error: module has imports, but imports are not supported\n");
            return;
        }
#else
        fprintf(stderr, "error: module has imports, but imports are not supported\n");
        return;
#endif
    }

    struct RunData {
        Module* module;
        ExternVector& importValues;
        std::string* exportToRun;
    } data = { module.value(), importValues, &exportToRun };
    Walrus::Trap trap;

    trap.run([](ExecutionState& state, void* d) {
        auto data = reinterpret_cast<RunData*>(d);
        Instance* instance = data->module->instantiate(state, data->importValues);

        for (auto&& exp : data->module->exports()) {
            if (exp->exportType() == ExportType::Function) {
                if (*data->exportToRun != exp->name() && *data->exportToRun != "*") {
                    continue;
                }

                auto fn = instance->function(exp->itemIndex());
                FunctionType* fnType = fn->asDefinedFunction()->moduleFunction()->functionType();

                if (!fnType->param().empty()) {
                    printf("warning: function %s has params, but params are not supported\n", exp->name().c_str());
                    return;
                }

                Walrus::ValueVector result;
                result.resize(fnType->result().size());
                fn->call(state, nullptr, result.data());

                for (auto&& r : result) {
                    switch (r.type()) {
                    case Value::I32: {
                        printf("%d\n", r.asI32());
                        break;
                    }
                    case Value::I64: {
                        printf("%" PRId64 "\n", r.asI64());
                        break;
                    }
                    case Value::F32: {
                        printf("%.8f\n", r.asF32());
                        break;
                    }
                    case Value::F64: {
                        printf("%.8lf\n", r.asF64());
                        break;
                    }
                    default:
                        printf("(unknown)\n");
                        break;
                    }
                }
            }
        }
    },
             &data);
}

namespace BW = wasm; // Binaryen Wasm
                     // Define Op as an alias for uint32_t.

using Op = uint32_t;


// Provide inline definitions for opcodes used in candidate lists.
// Type
inline uint32_t BinaryenTypeInt32() { return 0x7F; }

// Arithmetic (i32)
inline Op BinaryenI32Add() { return 0x6A; }
inline Op BinaryenI32Sub() { return 0x6B; }
inline Op BinaryenI32Mul() { return 0x6C; }
inline Op BinaryenI32DivS() { return 0x6D; }
inline Op BinaryenI32DivU() { return 0x6E; }
inline Op BinaryenI32And() { return 0x71; }
inline Op BinaryenI32Or() { return 0x72; }
inline Op BinaryenI32Xor() { return 0x73; }

// Arithmetic (i64)
inline Op BinaryenI64Add() { return 0x7C; }
inline Op BinaryenI64Sub() { return 0x7D; }
inline Op BinaryenI64Mul() { return 0x7E; }

// Floating-point (f32)
inline Op BinaryenF32Add() { return 0x92; }
inline Op BinaryenF32Sub() { return 0x93; }
inline Op BinaryenF32Mul() { return 0x94; }
inline Op BinaryenF32Div() { return 0x95; }

// Floating-point (f64)
inline Op BinaryenF64Add() { return 0xA0; }
inline Op BinaryenF64Sub() { return 0xA1; }
inline Op BinaryenF64Mul() { return 0xA2; }
inline Op BinaryenF64Div() { return 0xA3; }

// Control opcodes
inline Op BinaryenBrIf() { return 0x0D; }
inline Op BinaryenBr() { return 0x0C; }
inline Op BinaryenNop() { return 0x01; }
inline Op BinaryenIf() { return 0x04; }
inline Op BinaryenI32Eqz() { return 0x45; }

// Local variable opcodes
inline Op BinaryenLocalGet() { return 0x20; }
inline Op BinaryenLocalSet() { return 0x21; }
inline Op BinaryenLocalTee() { return 0x22; }

// Global variable opcodes
inline Op BinaryenGlobalGet() { return 0x23; }
inline Op BinaryenGlobalSet() { return 0x24; }

// Call opcodes
inline Op BinaryenCallFunction() { return 0x10; }
inline Op BinaryenCallIndirect() { return 0x11; }
inline Op BinaryenCallRef() { return 0x14; }

// Memory load opcodes
inline Op BinaryenI32Load() { return 0x28; }
inline Op BinaryenI32LoadMem8S() { return 0x2C; }
inline Op BinaryenI32LoadMem8U() { return 0x2D; }
inline Op BinaryenI32LoadMem16S() { return 0x2E; }
inline Op BinaryenI32LoadMem16U() { return 0x2F; }
inline Op BinaryenI64Load() { return 0x29; }

// Memory store opcodes
inline Op BinaryenI32Store() { return 0x36; }
inline Op BinaryenI64Store() { return 0x37; }

// Miscellaneous memory opcodes
inline Op BinaryenMemoryGrow() { return 0x40; }
inline Op BinaryenMemorySize() { return 0x3F; }

// SIMD opcodes
inline Op BinaryenS128Load() { return 0xfd00; }
inline Op BinaryenS128Load8Lane() { return 0xfd54; }
inline Op BinaryenS128Load16Lane() { return 0xfd55; }
inline Op BinaryenS128Load32Lane() { return 0xfd56; }

// Atomic opcodes
inline Op BinaryenI32AtomicLoad() { return 0xfe10; }
inline Op BinaryenI32AtomicLoad8U() { return 0xfe12; }
inline Op BinaryenI32AtomicLoad16U() { return 0xfe13; }

// GC opcodes
inline Op BinaryenStructNew() { return 0xfb00; }
inline Op BinaryenStructNewDefault() { return 0xfb01; }

//-----------------------------------------------------------------------------
// Parse a WASM module from binary data using Binaryen's API.
BW::Module* parseWasmModuleFromBinary(const uint8_t* data, size_t size)
{
    if (size < 8) {
        std::cerr << "Input size too small for a valid WASM module.\n";
        return nullptr;
    }

    if (data[0] != 0x00 || data[1] != 0x61 || data[2] != 0x73 || data[3] != 0x6d) {
        std::cerr << "Invalid WASM magic number.\n";
        return nullptr;
    }

    if (data[4] != 0x01 || data[5] != 0x00 || data[6] != 0x00 || data[7] != 0x00) {
        std::cerr << "Unsupported WASM version.\n";
        return nullptr;
    }


    BW::Module* module = new BW::Module();
    try {
        // FeatureSet (Set essential functions)
        BW::FeatureSet features = BW::FeatureSet::All;
        std::vector<char> input(data, data + size);
        // 1. Read Binary

        /*
        std::cerr << "[DEBUG] Input Data (First 8byte): ";
        for (size_t i = 0; i < std::min(size_t(8), input.size()); i++) {
            std::cerr << std::hex << (int)(unsigned char)input[i] << " ";
        }
        std::cerr << std::dec << "\n";
        */
        BW::ModuleReader reader; // module is BW::Module*
        reader.readBinaryData(input, *module, "");
    } catch (std::exception& e) {
        std::cerr << "Module parse error: " << e.what() << "\n";
        delete module;
        return nullptr;
    }
    return module;
}

//-----------------------------------------------------------------------------
// Walk the AST in postorder and collect pointers to all expressions.
std::vector<BW::Expression*> collectExpressions(BW::Expression* root)
{
    std::vector<BW::Expression*> result;
    struct Collector : public BW::PostWalker<Collector> {
        std::vector<BW::Expression*>& result;
        Collector(std::vector<BW::Expression*>& r)
            : result(r)
        {
        }
        void visitExpression(BW::Expression* curr) { result.push_back(curr); }
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
Op getReplacementForOp(Op opcode, std::mt19937& rng)
{
    // ----- Arithmetic (i32) opcodes -----
    if (opcode == BinaryenI32Add()) {
        std::vector<Op> candidates = { BinaryenI32Sub(), BinaryenI32Mul(),
                                       BinaryenI32DivS(), BinaryenI32DivU(),
                                       BinaryenI32And(), BinaryenI32Or(), BinaryenI32Xor() };
        std::uniform_int_distribution<size_t> dist(0, candidates.size() - 1);
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
        if (!candidates.empty())
            return candidates[rng() % candidates.size()];
    }
    // ----- Memory store opcodes -----
    if (opcode == BinaryenI32Store()) {
        std::vector<Op> candidates = { /* Add i32.store variants if available */ };
        if (!candidates.empty())
            return candidates[rng() % candidates.size()];
    } else if (opcode == BinaryenI64Store()) {
        std::vector<Op> candidates = { /* Add i64.store variants if available */ };
        if (!candidates.empty())
            return candidates[rng() % candidates.size()];
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
void mutateConstantExpressions(BW::Module* module, std::mt19937& rng)
{
    if (!module || module->functions.empty()) return;
    #ifdef PRINT_LOG
    std::cout << "[Custom Mutator] mutateConstantExpressions module with " << module->functions.size() << " functions\n";
    #endif
    for (auto& funcPtr : module->functions) {
        BW::Function* func = funcPtr.get();
        #ifdef PRINT_LOG
        std::cout << "[Custom Mutator] Processing functions: " << func->name.str << "\n";
        #endif
        std::vector<BW::Expression*> exprs = collectExpressions(func->body);
        for (auto* expr : exprs) {
            if (auto* c = expr->dynCast<BW::Const>()) {
                int choice = rng() % 2; // 0: bit flip, 1: extreme value injection
                if (c->type == BW::Type::i32) {
                    if (choice == 0) {
                        int32_t oldVal = c->value.geti32();
                        int bit = rng() % 32;
                        int32_t newVal = oldVal ^ (1 << bit);
                        c->value = BW::Literal(newVal);
                        #ifdef PRINT_LOG
                        std::cout << "[Custom Mutator] Function " << func->name.str
                            << ": i32 constant bit flip mutation - old value: " << oldVal
                            << ", flipped bit: " << bit
                            << ", new value: " << newVal << ".\n";
                        #endif
                    } else {
                        std::vector<int32_t> candidates = { 0, -1,
                                                            std::numeric_limits<int32_t>::max(), std::numeric_limits<int32_t>::min() };
                        int32_t chosen = candidates[rng() % candidates.size()];
                        c->value = BW::Literal(chosen);
                        #ifdef PRINT_LOG
                        std::cout << "[Custom Mutator] Function " << func->name.str
                                  << ": i32 constant extreme value injection - new value: " << chosen << ".\n";
                        #endif
                    }
                } else if (c->type == BW::Type::i64) {
                    if (choice == 0) {
                        int64_t oldVal = c->value.geti64();
                        int bit = rng() % 64;
                        int64_t newVal = oldVal ^ (1LL << bit);
                        c->value = BW::Literal(newVal);
                        #ifdef PRINT_LOG
                        std::cout << "[Custom Mutator] Function " << func->name.str 
                            << ": i64 constant bit flip mutation - old value: " << oldVal 
                            << ", flipped bit: " << bit 
                            << ", new value: " << newVal << ".\n";
                        #endif
                    } else {
                        std::vector<int64_t> candidates = { 0LL, -1LL,
                                                            std::numeric_limits<int64_t>::max(), std::numeric_limits<int64_t>::min() };
                        int64_t chosen = candidates[rng() % candidates.size()];
                        c->value = BW::Literal(chosen);
                        #ifdef PRINT_LOG
                        std::cout << "[Custom Mutator] Function " << func->name.str 
                                  << ": i64 constant extreme value injection - new value: " << chosen << ".\n";
                        #endif
                    }
                } else if (c->type == BW::Type::f32) {
                    if (choice == 0) {
                        float oldVal = c->value.getf32();
                        uint32_t bits;
                        memcpy(&bits, &oldVal, sizeof(bits));
                        int bit = rng() % 32;
                        bits ^= (1u << bit);
                        float newVal;
                        memcpy(&newVal, &bits, sizeof(newVal));
                        c->value = BW::Literal(newVal);
                        #ifdef PRINT_LOG
                        std::cout << "[Custom Mutator] Function " << func->name.str 
                            << ": f32 constant bit flip mutation - old value: " << oldVal 
                            << ", flipped bit: " << bit 
                            << ", new value: " << newVal << ".\n";
                        #endif
                    } else {
                        std::vector<float> candidates = { 0.0f, -0.0f,
                                                          std::numeric_limits<float>::infinity(), -std::numeric_limits<float>::infinity(),
                                                          std::numeric_limits<float>::quiet_NaN() };
                        float chosen = candidates[rng() % candidates.size()];
                        c->value = BW::Literal(chosen);
                        #ifdef PRINT_LOG
                        std::cout << "[Custom Mutator] Function " << func->name.str 
                                  << ": f32 constant extreme value injection - new value: " << chosen << ".\n";
                        #endif
                    }
                } else if (c->type == BW::Type::f64) {
                    if (choice == 0) {
                        double oldVal = c->value.getf64();
                        uint64_t bits;
                        memcpy(&bits, &oldVal, sizeof(bits));
                        int bit = rng() % 64;
                        bits ^= (1ULL << bit);
                        double newVal;
                        memcpy(&newVal, &bits, sizeof(newVal));
                        c->value = BW::Literal(newVal);
                        #ifdef PRINT_LOG
                        std::cout << "[Custom Mutator] Function " << func->name.str 
                            << ": f64 constant bit flip mutation - old value: " << oldVal 
                            << ", flipped bit: " << bit 
                            << ", new value: " << newVal << ".\n";
                        #endif
                    } else {
                        std::vector<double> candidates = { 0.0, -0.0,
                                                           std::numeric_limits<double>::infinity(), -std::numeric_limits<double>::infinity(),
                                                           std::numeric_limits<double>::quiet_NaN() };
                        double chosen = candidates[rng() % candidates.size()];
                        c->value = BW::Literal(chosen);
                        #ifdef PRINT_LOG
                        std::cout << "[LOG] Function " << func->name.str 
                                  << ": f64 constant extreme value injection - new value: " << chosen << ".\n";
                        #endif
                    }
                }
            }
        }
    }
}

//-----------------------------------------------------------------------------
// Section Mutation: Apply various structural transformations on the module
// to increase code diversity while preserving overall semantics as much as possible.
// This includes:
//   - Function addition: Insert a new dummy function with a valid signature.
//   - Function cloning: Duplicate an existing function (with a modified name).
//   - Function removal: Remove an existing function (preferably one that is unreferenced).
//   - Global variable insertion: Add a new global variable with a random initial value.
//   - Data section manipulation: Insert or modify a data segment.
// The extra options (global and data section mutations) are optional; remove them if not applicable.
// Revised mutateSection: Adds/clones/removes module sections.
// Note: This version now takes an extra parameter: a pointer to the Store.
// Revised mutateSection: Performs several section-level mutations on the module.
// Strategies include: adding a new dummy function, cloning an existing function,
// removing the last function, inserting a new global variable, and modifying a data segment.
void mutateSection(BW::Module* module, Store* store, std::mt19937& rng) {
    if (!module || module->functions.empty()) return;
  
    int option = rng() % 5;
    BW::Builder builder(*module);
  
    if (option == 0) {
      // Option 0: Add a new dummy function.
      #ifdef PRINT_LOG
      std::cout << "[Custom Mutator] Section mutation: Adding new dummy function.\n";
      #endif
      BW::Function* newFunc = new BW::Function();
      newFunc->name = BW::Name("fuzz_dummy");

      // Copy the function type from an existing function.
      newFunc->type = module->functions[0]->type;
      
      // Create a simple function body: drop a constant.
      BW::Expression* constExpr = builder.makeConst(BW::Literal(int32_t(0)));
      BW::Expression* dropExpr = builder.makeDrop(constExpr);
      newFunc->body = dropExpr;
      module->addFunction(newFunc);
      #ifdef PRINT_LOG
      std::cout << "[Custom Mutator] Section mutation: New function '"
                << newFunc->name.str << "' added.\n";
      #endif
    } else if (option == 1) {
      // Option 1: Clone an existing function.
      if (!module->functions.empty()) {
        size_t idx = rng() % module->functions.size();
        BW::Function* orig = module->functions[idx].get();
        BW::Function* clone = new BW::Function(*orig);

        // Append "_clone" to the original function's name.
        clone->name = BW::Name(std::string(orig->name.str) + "_clone");
        module->addFunction(clone);
        #ifdef PRINT_LOG
        std::cout << "[Custom Mutator] Section mutation: Cloned function '"
                  << orig->name.str << "' to '" << clone->name.str << "'.\n";
        #endif
      }
    } else if (option == 2) {
      // Option 2: Remove the last function.
      if (!module->functions.empty()) {
        std::string name = std::string(module->functions.back()->name.str);
        module->removeFunction(name);
        #ifdef PRINT_LOG
        std::cout << "[Custom Mutator] Section mutation: Removed function '" << name << "'.\n";
        #endif
      }
    } else if (option == 3) {
      // Option 3: Insert a new global variable.
      #ifdef PRINT_LOG
      std::cout << "[Custom Mutator] Section mutation: Adding new global variable.\n";
      #endif
      
      /*
      // Generate a random int32 value.
      int32_t randVal = static_cast<int32_t>(rng());
      
      // Create a new global by constructing a unique_ptr to Global.
      auto newGlobal = std::make_unique<BW::Global>();
      
      // Create a Type object from the uint32_t returned by BinaryenTypeInt32();
      BW::Type int32Type(BinaryenTypeInt32());

      // Set the global's tyype.      
      newGlobal->type = int32Type;
      
      // Mark the global as mutable.
      newGlobal->mutable_ = true;
      
      // Initialize the global's value with a constant.
      newGlobal->init = builder.makeConst(BW::Literal(int32_t(randVal)));
      
      // Set an export name for tracking.
      newGlobal->name = BW::Name("fuzz_global");
      
      // Add the new global to the module.
      module->addGlobal(std::move(newGlobal));
      */

      int32_t randVal = static_cast<int32_t>(rng());

      auto* newGlobal = new wasm::Global();
      newGlobal->name = BW::Name("fuzz_global");
      newGlobal->mutable_ = true;
      newGlobal->type = wasm::Type::i32;
      newGlobal->init = builder.makeConst(BW::Literal(randVal));
      module->addGlobal(newGlobal);    
      #ifdef PRINT_LOG
      std::cout << "[Custom Mutator] Section mutation: New global variable 'fuzz_global' added with initial value "
                << randVal << ".\n";
      #endif
    } else if (option == 4) {
      // Option 4: Modify the data section.
      if (!module->dataSegments.empty()) {
        #ifdef PRINT_LOG
        std::cout << "[Custom Mutator] Section mutation: Modifying a data segment.\n";
        #endif
        size_t idx = rng() % module->dataSegments.size();
        auto& dataSeg = module->dataSegments[idx];
        const char extra[] = "FUZZ";
        dataSeg->data.insert(dataSeg->data.end(), extra, extra + sizeof(extra) - 1);
        #ifdef PRINT_LOG
        std::cout << "[Custom Mutator] Section mutation: Appended 'FUZZ' to data segment " << idx << ".\n";
        #endif
      } else {
        #ifdef PRINT_LOG
        std::cout << "[Custom Mutator] Section mutation: No data segments available to modify.\n";
        #endif
      }
    }
  }

// Helper function: Find a block in the AST that contains the target expression.
BW::Block* findParentBlock(BW::Expression* target, const std::vector<BW::Expression*>& exprs) {
    for (auto* expr : exprs) {
        if (auto* block = expr->dynCast<BW::Block>()) {
            for (auto* child : block->list) {
                if (child == target) {
                    return block;
                }
            }
        }
    }
    return nullptr;
}

//-----------------------------------------------------------------------------
// Semantic Mutation: Insert dead code into a function's body or apply equivalent 
// transformations without changing the program semantics. This increases the 
// coverage by generating diverse code structures.
// Strategies include:
// - Inserting an if(false){...} block (dead code)
// - Inserting a drop of a no-op arithmetic expression
// - Transforming an i32.add into an equivalent form (x + y -> (x+0) + y)
// - Duplicating an instruction in its parent block
// - Inserting an if(false){unreachable} block
void mutateSemantic(BW::Module* module, std::mt19937& rng)
{
    if (!module || module->functions.empty()) return;

    // Select a random function from the module.
    BW::Function* func = module->functions[rng() % module->functions.size()].get();
    #ifdef PRINT_LOG
    std::cout << "[Custom Mutator] Semantic mutation: Processing function '"
              << func->name.str << "'.\n";
    #endif
    BW::Builder builder(*module);

    // Choose among 5 semantic-preserving mutation strategies.
    int option = rng() % 4;
    switch (option) {
        case 0: {
            // Option 0: Insert dead code with an if(false){...} block.
            BW::Expression* falseConst = builder.makeConst(BW::Literal(int32_t(0)));
            BW::Expression* nopExpr = builder.makeNop();
            BW::Expression* ifBlock = builder.makeBlock({ nopExpr });
            BW::Expression* ifExpr = builder.makeIf(falseConst, ifBlock);
            // Insert the if-block at the beginning of the function body.
            if (auto* block = func->body->dynCast<BW::Block>()) {
                block->list.push_back(ifExpr);
                if (block->list.size() > 1) {
                    std::swap(block->list[0], block->list.back());
                }
            } else {
                func->body = builder.makeBlock({ ifExpr, func->body });
            }
            #ifdef PRINT_LOG
            std::cout << "[Custom Mutator] Inserted if(false) dead code block.\n";
            #endif
            break;
        }
        /*
        case 1: {
            // Option 1: Insert a drop instruction wrapping a no-op arithmetic expression.
            // BW::Expression* zero = builder.makeConst(BW::Literal(int32_t(0)));
            const uint8_t simdZeros[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            BW::Expression* zero = builder.makeConst(BW::Literal(simdZeros));
            BW::Expression* addExpr = builder.makeBinary(static_cast<BW::BinaryOp>(BinaryenI32Add()), zero, zero);
            BW::Expression* dropExpr = builder.makeDrop(addExpr);
            
            BW::Type bodyType = func->body->type;
            bool isSafeToInsertDrop = (bodyType == BW::Type::none);

            if (isSafeToInsertDrop) {
                if (auto* block = func->body->dynCast<BW::Block>()) {
                    block->list.push_back(dropExpr);
                    if (block->list.size() > 1) {
                        std::swap(block->list[0], block->list.back());
                    }
                } else {
                    func->body = builder.makeBlock({ dropExpr, func->body });
                }
            }
            // #ifdef PRINT_LOG
            std::cout << "[Custom Mutator] Inserted drop of no-op arithmetic expression.\n";
            // #endif
            break;
        }
        */
        case 1: {
            // Option 2: Transform an i32.add into an equivalent form: (x + 0) + y.
            std::vector<BW::Expression*> binExprs = collectExpressions(func->body);
            bool transformed = false;
            for (auto* expr : binExprs) {
                if (auto* binary = expr->dynCast<BW::Binary>()) {
                    if (binary->op == BinaryenI32Add()) {
                        BW::Expression* zero = builder.makeConst(BW::Literal(int32_t(0)));
                        BW::Expression* newLeft = builder.makeBinary(static_cast<BW::BinaryOp>(BinaryenI32Add()), binary->left, zero);
                        binary->left = newLeft;
                        #ifdef PRINT_LOG
                        std::cout << "[Custom Mutator] Transformed i32.add to equivalent form (x+0+y).\n";
                        #endif
                        transformed = true;
                        break; // Apply transformation once per function.
                    }
                }
            }
            if (!transformed) {
                #ifdef PRINT_LOG
                std::cout << "[Custom Mutator] No suitable binary arithmetic expression found for transformation.\n";
                #endif
            }
            break;
        }
        case 2: {
            // Option 3: Duplicate an instruction to alter internal structure.
            std::vector<BW::Expression*> allExprs = collectExpressions(func->body);
            bool duplicated = false;
            for (auto* expr : allExprs) {
                if (auto* binary = expr->dynCast<BW::Binary>()) {
                    BW::Block* parentBlock = findParentBlock(binary, allExprs);
                    if (parentBlock) {
                        parentBlock->list.push_back(binary);
                        #ifdef PRINT_LOG
                        std::cout << "[Custom Mutator] Duplicated a binary expression in function '"
                                  << func->name.str << "'.\n";
                        #endif
                        duplicated = true;
                        break;
                    }
                }
            }
            if (!duplicated) {
                #ifdef PRINT_LOG
                std::cout << "[Custom Mutator] No expression found for duplication in function '"
                          << func->name.str << "'.\n";
                #endif
            }
            break;
        }
        case 3: {
            // Option 4: Insert an unreachable instruction inside an if(false){...} block.
            BW::Expression* falseConst = builder.makeConst(BW::Literal(int32_t(0)));
            BW::Expression* unreachableExpr = builder.makeUnreachable();
            BW::Expression* ifBlock = builder.makeBlock({ unreachableExpr });
            BW::Expression* ifExpr = builder.makeIf(falseConst, ifBlock);
            if (auto* block = func->body->dynCast<BW::Block>()) {
                block->list.push_back(ifExpr);
                if (block->list.size() > 1) {
                    std::swap(block->list[0], block->list.back());
                }
            } else {
                func->body = builder.makeBlock({ ifExpr, func->body });
            }
            #ifdef PRINT_LOG
            std::cout << "[Custom Mutator] Inserted if(false) block containing unreachable code.\n";
            #endif
            break;
        }
        default:
            break;
    }
    #ifdef PRINT_LOG
    std::cout << "[Custom Mutator] Semantic mutation: Completed processing function '"
              << func->name.str << "'.\n";
    #endif
}

//-----------------------------------------------------------------------------
// Control-Flow Mutation: Modify branch conditions in control expressions.
void mutateControlFlow(BW::Module* module, std::mt19937& rng)
{
    if (!module || module->functions.empty()) return;
    
    // Iterate through each function.
    for (auto& funcPtr : module->functions) {
        BW::Function* func = funcPtr.get();
        std::vector<BW::Expression*> exprs = collectExpressions(func->body);
        bool mutated = false;
        
        // Process each expression.
        for (auto* expr : exprs) {
            // --- Option 1: Mutate conditional branch (Break) instructions ---
            if (auto* br = expr->dynCast<BW::Break>()) {
                if (br->condition) {
                    // Choose among three mutation strategies:
                    // 0: Toggle the condition (wrap with i32.eqz)
                    // 1: Remove the condition (set to Nop)
                    // 2: Replace the condition with a constant (true or false)
                    int option = rng() % 3;
                    #ifdef PRINT_LOG
                    std::cout << "[Custom Mutator] Control-Flow mutation in function '"
                              << func->name.str << "': ";
                    #endif
                    if (option == 0) {
                        BW::Expression* oldCond = br->condition;
                        BW::Expression* newCond = BW::Builder(*module).makeUnary(
                            static_cast<BW::UnaryOp>(BinaryenI32Eqz()), oldCond);
                        br->condition = newCond;
                        #ifdef PRINT_LOG
                        std::cout << "Toggled branch condition.\n";
                        #endif
                    } else if (option == 1) {
                        br->condition = BW::Builder(*module).makeNop();
                        #ifdef PRINT_LOG
                        std::cout << "Removed branch condition.\n";
                        #endif
                    } else {
                        int boolVal = rng() % 2; // 0: false, 1: true
                        BW::Expression* constCond = BW::Builder(*module).makeConst(
                            BW::Literal(int32_t(boolVal ? 1 : 0)));
                        br->condition = constCond;
                        #ifdef PRINT_LOG
                        std::cout << "Replaced branch condition with constant "
                                  << (boolVal ? "true" : "false") << ".\n";
                        #endif
                    }
                    mutated = true;
                }
                // --- Option 2: Mutate branch target labels ---
                if (!(br->name == BW::Name()) && (rng() % 2 == 0)) {
                    std::string oldLabel = std::string(br->name.str);
                    std::string newLabel = oldLabel + "_mut";
                    br->name = BW::Name(newLabel);
                    #ifdef PRINT_LOG
                    std::cout << "[Custom Mutator] Changed branch target label from '"
                              << oldLabel << "' to '" << newLabel << "'.\n";
                    #endif
                    mutated = true;
                }
            }
            // --- Option 3: Mutate loop constructs ---
            else if (auto* loop = expr->dynCast<BW::Loop>()) {
                // Example mutation: force an early exit from the loop by inserting a break at the beginning.
                #ifdef PRINT_LOG
                std::cout << "[Custom Mutator] Found Loop in function '" << func->name.str << "'.\n";
                #endif
                BW::Builder builder(*module);
                BW::Expression* breakExpr = builder.makeBreak(
                    BW::Name("break_mut"), nullptr, builder.makeConst(BW::Literal(int32_t(1))));

                if (auto* block = loop->body->dynCast<BW::Block>()) {
                    // push_back and then rotate the bolck's list
                    block->list.push_back(breakExpr);
                    std::rotate(block->list.begin(), block->list.end() - 1, block->list.end());
                    #ifdef PRINT_LOG
                    std::cout << "[Custom Mutator] Inserted break at beginning of loop.\n";
                    #endif
                } else {
                    // If the loop body is not a block, wrap it in a block and insert the break.
                    BW::Expression* newBody = builder.makeBlock({ breakExpr, loop->body });
                    loop->body = newBody;
                    #ifdef PRINT_LOG
                    std::cout << "[Custom Mutator] Wrapped loop body in block with an inserted break.\n";
                    #endif
                }
                mutated = true;
            }
        }
        
        if (!mutated) {
            #ifdef PRINT_LOG
            std::cout << "[Custom Mutator] No control-flow mutations applied in function '"
                      << func->name.str << "'.\n";
            #endif
        }
    }
}


//-----------------------------------------------------------------------------
// Vulnerability Injection: Modify memory access offsets to huge values,
// and inject an invalid type index in call_indirect if possible.
// 5. Vulnerability Injection: Because the target of call_indirect must be Expression*, it generates a constant expression.
void injectVulnerability(BW::Module* module, std::mt19937& rng)
{
    if (!module || module->functions.empty()) return;
    #ifdef PRINT_LOG
    std::cout << "[Custom Mutator] Starting vulnerability injection.\n";
    #endif
    // Iterate over each function.
    for (auto& funcPtr : module->functions) {
        BW::Function* func = funcPtr.get();
        std::vector<BW::Expression*> exprs = collectExpressions(func->body);

        // Optionally inject a recursive call to provoke a stack overflow (50% chance).
        if (rng() % 2 == 0) {
            BW::Builder builder(*module);
            // Use a void type for the recursive call.
            // In Binaryen, void is typically represented as BinaryenTypeNone(),
            // but if that's unavailable, we cast 0 to BW::Type.
            BW::Type noneType = static_cast<BW::Type>(0);
            // Create a call to itself.
            BW::Expression* recCall = builder.makeCall(func->name, std::vector<BW::Expression*>(), noneType, false);
            // Insert the recursive call at the beginning of the function body.
            if (auto* block = func->body->dynCast<BW::Block>()) {
                // Since ArenaVector may not support insert(), push_back then swap with the first element.
                block->list.push_back(recCall);
                if (block->list.size() > 1) {
                    std::swap(block->list[0], block->list.back());
                }
            } else {
                func->body = builder.makeBlock({ recCall, func->body });
            }
            #ifdef PRINT_LOG
            std::cout << "[Custom Mutator] Function '" << func->name.str
                      << "': Inserted recursive call to provoke stack overflow.\n";
            #endif
        }

        // Process each expression in the function.
        for (auto* expr : exprs) {
            // --- Memory Load/Store Vulnerability ---
            if (auto* load = expr->dynCast<BW::Load>()) {
                int option = rng() % 2;
                if (option == 0) {
                    load->offset = 0xFFFFFFFF;
                    #ifdef PRINT_LOG
                    std::cout << "[Custom Mutator] Function '" << func->name.str
                              << "': Set memory load offset to 0xFFFFFFFF.\n";
                    #endif
                } else {
                    load->offset = 0xFFFFFFF0;
                    #ifdef PRINT_LOG
                    std::cout << "[Custom Mutator] Function '" << func->name.str
                              << "': Set memory load offset to 0xFFFFFFF0.\n";
                    #endif
                }
            } else if (auto* store = expr->dynCast<BW::Store>()) {
                int option = rng() % 2;
                if (option == 0) {
                    store->offset = 0xFFFFFFFF;
                    #ifdef PRINT_LOG
                    std::cout << "[Custom Mutator] Function '" << func->name.str
                              << "': Set memory store offset to 0xFFFFFFFF.\n";
                    #endif
                } else {
                    store->offset = 0xFFFFFFF0;
                    #ifdef PRINT_LOG
                    std::cout << "[Custom Mutator] Function '" << func->name.str
                              << "': Set memory store offset to 0xFFFFFFF0.\n";
                    #endif
                }
            }
            // --- CallIndirect Vulnerability ---
            else if (auto* callIndirect = expr->dynCast<BW::CallIndirect>()) {
                int option = rng() % 3;
                if (option == 0) {
                    // Use an out-of-bound index.
                    callIndirect->target = BW::Builder(*module).makeConst(
                        BW::Literal((uint32_t)0xFFFFFFFF));
                    #ifdef PRINT_LOG
                    std::cout << "[Custom Mutator] Function '" << func->name.str
                              << "': Set call_indirect target to 0xFFFFFFFF (invalid index).\n";
                    #endif
                } else if (option == 1) {
                    // Use zero as target.
                    callIndirect->target = BW::Builder(*module).makeConst(
                        BW::Literal((uint32_t)0));
                    #ifdef PRINT_LOG
                    std::cout << "[Custom Mutator] Function '" << func->name.str
                              << "': Set call_indirect target to 0.\n";
                    #endif
                } else {
                    // Leave it unchanged.
                    #ifdef PRINT_LOG
                    std::cout << "[Custom Mutator] Function '" << func->name.str
                              << "': Left call_indirect target unchanged.\n";
                    #endif
                }
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
void mutateInstructions(BW::Module* module, std::mt19937& rng)
{
    if (!module || module->functions.empty()) return;
    // Iterate over every function in the module.
    for (auto& funcPtr : module->functions) {
        BW::Function* func = funcPtr.get();
        #ifdef PRINT_LOG
        std::cout << "[Custom Mutator] Mutating instructions in function '" << func->name.str << "'.\n";
        #endif
        // Collect all expressions in the function body.
        std::vector<BW::Expression*> exprs = collectExpressions(func->body);
        #ifdef PRINT_LOG
        std::cout << "[Custom Mutator] Collected " << exprs.size() << " expressions.\n";
        #endif
        // Process each expression.
        for (auto* expr : exprs) {
            // ----- Binary Expressions -----
            if (auto* binary = expr->dynCast<BW::Binary>()) {
                if (binary->left->type == BW::Type::i32 && binary->right->type == BW::Type::i32) {
                    #ifdef PRINT_LOG
                    std::cout << "[Custom Mutator] Function '" << func->name.str 
                              << "': Found Binary expression with opcode " << binary->op << ".\n";
                    #endif

                    // Define i32 operator
                    std::vector<Op> validI32Ops = { 
                        BinaryenI32Add(), BinaryenI32Sub(), BinaryenI32Mul(),
                        BinaryenI32DivS(), BinaryenI32DivU(),
                        BinaryenI32And(), BinaryenI32Or(), BinaryenI32Xor() 
                    };

                    // Replace opcode using candidate list based on its category.
                    Op newOp = getReplacementForOp(binary->op, rng);

                    if (std::find(validI32Ops.begin(), validI32Ops.end(), newOp) == validI32Ops.end()) {
                        #ifdef PRINT_LOG
                        std::cout << "[Custom Mutator] Function '" << func->name.str 
                                  << "': Candidate opcode " << newOp << " is not valid for i32, skipping mutation.\n";
                        #endif
                        continue;
                    }

                    // Determine if the operation is commutative.
                    bool commutative = false;
                    if (binary->op == BinaryenI32Add() || binary->op == BinaryenI32Mul() ||
                        binary->op == BinaryenI32And() || binary->op == BinaryenI32Or()  ||
                        binary->op == BinaryenI32Xor() || binary->op == BinaryenF32Add() ||
                        binary->op == BinaryenF32Mul() || binary->op == BinaryenF64Add() ||
                        binary->op == BinaryenF64Mul()) {
                        commutative = true;
                    }

                    // Randomly swap operands for commutative operations.
                    if (commutative && (rng() % 2 == 0)) {
                        std::swap(binary->left, binary->right);
                        #ifdef PRINT_LOG
                        std::cout << "[Custom Mutator] Function '" << func->name.str 
                                << "': Swapped operands in Binary expression.\n";
                        #endif
                    }

                    // Cast newOp (Op) to BinaryOp and log the change.
                    #ifdef PRINT_LOG
                    std::cout << "[Custom Mutator] Function '" << func->name.str 
                            << "': Replacing opcode " << binary->op << " with " << newOp << ".\n";
                    #endif
                    binary->op = static_cast<BW::BinaryOp>(newOp);
                }
            }
            // ----- Unary Expressions -----
            else if (auto* unary = expr->dynCast<BW::Unary>()) {
                if (unary->op == static_cast<BW::UnaryOp>(BinaryenI32Eqz())) {
                    #ifdef PRINT_LOG
                    std::cout << "[Custom Mutator] Function '" << func->name.str 
                              << "': Found Unary expression with i32.eqz opcode.\n";
                    #endif
                    std::vector<Op> candidates = { BinaryenNop() };
                    Op chosen = candidates[rng() % candidates.size()];
                    unary->op = static_cast<BW::UnaryOp>(chosen);
                    #ifdef PRINT_LOG
                    std::cout << "[Custom Mutator] Function '" << func->name.str 
                              << "': Replaced Unary opcode with " << chosen << ".\n";
                    #endif
                }
            }
            // ----- Call Expressions -----
            else if (auto* call = expr->dynCast<BW::Call>()) {
                #ifdef PRINT_LOG
                std::cout << "[Custom Mutator] Function '" << func->name.str 
                          << "': Found Call expression targeting '" << call->target.str << "'.\n";
                #endif
                if (!module->functions.empty()) {
                    std::vector<std::string> candidateTargets;
                    for (auto& fPtr : module->functions) {
                        BW::Function* f = fPtr.get();
                        if (f->name.str != call->target.str) {
                            candidateTargets.push_back(std::string(f->name.str));
                        }
                    }
                    if (!candidateTargets.empty()) {
                        std::uniform_int_distribution<size_t> dist(0, candidateTargets.size() - 1);
                        std::string newTarget = candidateTargets[dist(rng)];
                        call->target = BW::Name(newTarget);
                        #ifdef PRINT_LOG
                        std::cout << "[Custom Mutator] Function '" << func->name.str 
                                  << "': Changed Call target to '" << newTarget << "'.\n";
                        #endif
                    }
                }
            }
            // ----- CallIndirect Expressions -----
            else if (auto* callIndirect = expr->dynCast<BW::CallIndirect>()) {
                #ifdef PRINT_LOG
                std::cout << "[Custom Mutator] Function '" << func->name.str 
                          << "': Found CallIndirect expression. Setting target to 0.\n";
                #endif
                // Instead of using module->types (which is unavailable), choose a fixed value.
                callIndirect->target = BW::Builder(*module).makeConst(BW::Literal((uint32_t)0));
            }
            // ----- Memory Load Expressions -----
            else if (auto* load = expr->dynCast<BW::Load>()) {
                #ifdef PRINT_LOG
                std::cout << "[Custom Mutator] Function '" << func->name.str 
                          << "': Found Memory Load expression. ";
                #endif
                // Adjust the 'bytes' field to a candidate value and update alignment.
                std::vector<unsigned> candidateBytes = { 1, 2, 4, 8 };
                unsigned chosenBytes = candidateBytes[rng() % candidateBytes.size()];
                load->bytes = chosenBytes;
                load->align = chosenBytes;
                #ifdef PRINT_LOG
                std::cout << "Set bytes to " << chosenBytes << " and alignment to " << chosenBytes << ".\n";
                #endif
            }
            // ----- Memory Store Expressions -----
            else if (auto* store = expr->dynCast<BW::Store>()) {
                #ifdef PRINT_LOG
                std::cout << "[Custom Mutator] Function '" << func->name.str 
                          << "': Found Memory Store expression. ";
                #endif
                // Adjust the 'bytes' field for store expressions similarly.
                std::vector<unsigned> candidateBytes = { 1, 2, 4, 8 };
                unsigned chosenBytes = candidateBytes[rng() % candidateBytes.size()];
                store->bytes = chosenBytes;
                store->align = chosenBytes;
                #ifdef PRINT_LOG
                std::cout << "Set bytes to " << chosenBytes << " and alignment to " << chosenBytes << ".\n";
                #endif
            }
            // ----- Select Expressions -----
            else if (auto* sel = expr->dynCast<BW::Select>()) {
                #ifdef PRINT_LOG
                std::cout << "[Custom Mutator] Function '" << func->name.str 
                          << "': Found Select expression. ";
                #endif
                if (rng() % 2 == 0) {
                    std::swap(sel->ifTrue, sel->ifFalse);
                    #ifdef PRINT_LOG
                    std::cout << "Swapped ifTrue and ifFalse operands.\n";
                    #endif
                } else {
                    if (sel->condition && sel->condition->type == BW::Type::i32) {
                        BW::Expression* newCond = BW::Builder(*module).makeUnary(static_cast<BW::UnaryOp>(BinaryenI32Eqz()), sel->condition);
                        sel->condition = newCond;
                        #ifdef PRINT_LOG
                        std::cout << "Modified condition using i32.eqz.\n";
                        #endif
                    }
                }
            }
            // ----- Drop Expressions -----
            else if (auto* drop = expr->dynCast<BW::Drop>()) {
                #ifdef PRINT_LOG
                std::cout << "[Custom Mutator] Function '" << func->name.str 
                          << "': Found Drop expression. ";
                #endif
                // Optionally, wrap the drop's value with a block that inserts a Nop.
                if (rng() % 2 == 0) {
                    BW::Expression* nopExpr = BW::Builder(*module).makeNop();
                    drop->value = BW::Builder(*module).makeBlock({ nopExpr, drop->value });
                    #ifdef PRINT_LOG
                    std::cout << "Wrapped value in a block with a Nop.\n";
                    #endif
                }
            }
            // ----- Block Expressions -----
            else if (auto* block = expr->dynCast<BW::Block>()) {
                if (!block->list.empty() && (rng() % 2 == 0)) {
                    size_t idx = rng() % block->list.size();
                    BW::Expression* duplicate = block->list[idx]; // shallow copy; deep clone is preferable
                    // ArenaVector may not support insert; use push_back to duplicate the statement.
                    block->list.push_back(duplicate);
                    #ifdef PRINT_LOG
                    std::cout << "[Custom Mutator] Function '" << func->name.str 
                              << "': Duplicated a statement in Block expression.\n";
                    #endif
                }
            }
            // Additional cases for other expression types (e.g. Loop, If, etc.) can be added here.
        }
    }
}



// libFuzzer Entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
    try {
        std::vector<uint8_t> input(Data, Data + Size);
        std::string filename("fuzz.wasm");
        Engine* engine = new Engine();
        Store* store = new Store(engine);
        DefinedFunctionTypes functionTypes;
        Walrus::Trap::TrapResult trapResult = executeWASM(store, filename, input, functionTypes);

        // finalize
        delete store;
        delete engine;
        return 0;
    } catch (const std::exception &e) {
        // leabe or ignore logs in case of exceptions and return original data
        fprintf(stderr, "[fuzz] std::exception: %s\n", e.what());
        return Size;
    } catch ( ... ) {
        // handling all kinds of exceptions
        // abort(); // fuzzer recognize exception as crash
        fprintf(stderr, "[fuzz] LLVMFuzzerTestOneInput: unknown exception thrown\n");
        return Size;
    }
}

//-----------------------------------------------------------------------------
// Main custom mutator function for libFuzzer.
// This function parses the input WASM binary using Binaryen, randomly selects one
// of six mutation strategies (instruction, constant, section, semantic, control-flow,
// vulnerability injection), applies it, validates the mutated module, and then
// serializes it back to binary.
extern "C" size_t LLVMFuzzerCustomMutator(uint8_t* Data, size_t Size, size_t MaxSize, unsigned int Seed)
{
    if (Size < 8) {
        // fprintf(stderr, "custom mutator cov test Size: %ld", Size);
        static const uint8_t dummy_module[] = {
            0x00, 0x61, 0x73, 0x6d, // "\0asm" magic number
            0x01, 0x00, 0x00, 0x00,   // WASM version 1
            // Type Section (ID=1):
            0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 
            // Function Section (ID=3):
            0x03, 0x02, 0x01, 0x00,
            // Code Section (ID=10):
            0x0A, 0x04, 0x01,       // code section header: length=4, count=1
            0x02, 0x00, 0x0B        // body size=2, local decl count=0, end opcode (0x0B)
        };

        size_t dummySize = sizeof(dummy_module);
        if (dummySize <= MaxSize) {
            memcpy(Data, dummy_module, dummySize);
            Size = dummySize; // size update -> go try block
        } else {
            return Size;
        }
    }
    try {
        std::mt19937 rng(Seed);
        BW::Module* module = parseWasmModuleFromBinary(Data, Size);
        /*
        if (!module) {
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
            size_t dummySize = sizeof(dummy_module);
            if (dummySize <= MaxSize) {
                memcpy(Data, dummy_module, dummySize);
                return dummySize;
            }
            return Size; // fallback
        }
        */
        if (!module) {
            // parsing fail -> return original data
            return Size;
        }

        if (module->functions.empty()) {
            delete module;
            return Size;
        }

        Engine* dummyEngine = new Engine();
        Store* dummyStore = new Store(dummyEngine);

        int strat = rng() % 6;
        // fprintf(stderr, "custom mutator cov test strat: %d", strat);
        switch (strat) {
        case 0:
            mutateInstructions(module, rng);
            break;
        case 1:
            mutateConstantExpressions(module, rng);
            break;
        case 2:
            mutateSection(module, dummyStore, rng);
            break;
        case 3:
            mutateSemantic(module, rng);
            break;
        case 4:
            mutateControlFlow(module, rng);
            break;
        case 5:
            injectVulnerability(module, rng);
            break;
        default:
            break;
        }

        // Validate the mutated module using the static validate function.
        if (!BW::WasmValidator().validate(*module)) {
            #ifdef PRINT_LOG
            fprintf(stderr, "[Validator] Warning: mutated module did not pass validation, but returning it anyway.\n");
            #endif
            delete module;
            return Size; // Return original input if mutation is invalid.
        }

        BW::PassOptions passOpts;
        BW::BufferWithRandomAccess output;
        BW::WasmBinaryWriter writer(module, output, passOpts);
        writer.write();

        size_t outSize = output.size();
        size_t newSize = std::min(outSize, MaxSize);
        memcpy(Data, output.data(), newSize);

        delete module;
        delete dummyStore;
        delete dummyEngine;
        return newSize;
    } catch (const std::exception &e) {
        fprintf(stderr, "[fuzz] std::exception: %s\n", e.what());
        return Size;
    } catch (...) {
        abort(); // fuzzer recognize exception as crash
        // fprintf(stderr, "[fuzz] LLVMFuzzerCustomMutator: unknown exception thrown\n");
        return Size;
    }
}
