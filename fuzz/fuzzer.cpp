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

using Op = uint32_t; // Define Op as an alias for uint32_t.

// Provide inline definitions for opcodes used in candidate lists.
// https://github.com/WebAssembly/spec/blob/main/proposals/simd/NewOpcodes.md
// https://github.com/WebAssembly/spec/blob/main/proposals/simd/SIMD.md


inline Op BinaryenUnreachable() { return 0x0000; }
inline Op BinaryenNop() { return 0x0001; }
inline Op BinaryenBlock() { return 0x0002; }
inline Op BinaryenLoop() { return 0x0003; }
inline Op BinaryenIf() { return 0x0004; }
inline Op BinaryenElse() { return 0x0005; }
inline Op BinaryenTry() { return 0x0006; }
inline Op BinaryenCatch() { return 0x0007; }
inline Op BinaryenThrow() { return 0x0008; }
inline Op BinaryenRethrow() { return 0x0009; }
inline Op BinaryenEnd() { return 0x000B; }
inline Op BinaryenBr() { return 0x000C; }
inline Op BinaryenBrIf() { return 0x000D; }
inline Op BinaryenBrTable() { return 0x000E; }
inline Op BinaryenReturn() { return 0x000F; }
inline Op BinaryenCall() { return 0x0010; }
inline Op BinaryenCallIndirect() { return 0x0011; }
inline Op BinaryenReturnCall() { return 0x0012; }
inline Op BinaryenReturnCallIndirect() { return 0x0013; }
inline Op BinaryenCallRef() { return 0x0014; }
inline Op BinaryenDelegate() { return 0x0018; }
inline Op BinaryenCatchAll() { return 0x0019; }
inline Op BinaryenDrop() { return 0x001A; }
inline Op BinaryenSelect() { return 0x001B; }
inline Op BinaryenSelectT() { return 0x001C; }
inline Op BinaryenLocalGet() { return 0x0020; }
inline Op BinaryenLocalSet() { return 0x0021; }
inline Op BinaryenLocalTee() { return 0x0022; }
inline Op BinaryenGlobalGet() { return 0x0023; }
inline Op BinaryenGlobalSet() { return 0x0024; }
inline Op BinaryenI32Load() { return 0x0028; }
inline Op BinaryenI64Load() { return 0x0029; }
inline Op BinaryenF32Load() { return 0x002A; }
inline Op BinaryenF64Load() { return 0x002B; }
inline Op BinaryenI32Load8S() { return 0x002C; }
inline Op BinaryenI32Load8U() { return 0x002D; }
inline Op BinaryenI32Load16S() { return 0x002E; }
inline Op BinaryenI32Load16U() { return 0x002F; }
inline Op BinaryenI64Load8S() { return 0x0030; }
inline Op BinaryenI64Load8U() { return 0x0031; }
inline Op BinaryenI64Load16S() { return 0x0032; }
inline Op BinaryenI64Load16U() { return 0x0033; }
inline Op BinaryenI64Load32S() { return 0x0034; }
inline Op BinaryenI64Load32U() { return 0x0035; }
inline Op BinaryenI32Store() { return 0x0036; }
inline Op BinaryenI64Store() { return 0x0037; }
inline Op BinaryenF32Store() { return 0x0038; }
inline Op BinaryenF64Store() { return 0x0039; }
inline Op BinaryenI32Store8() { return 0x003A; }
inline Op BinaryenI32Store16() { return 0x003B; }
inline Op BinaryenI64Store8() { return 0x003C; }
inline Op BinaryenI64Store16() { return 0x003D; }
inline Op BinaryenI64Store32() { return 0x003E; }
inline Op BinaryenMemorySize() { return 0x003F; }
inline Op BinaryenMemoryGrow() { return 0x0040; }
inline Op BinaryenI32Const() { return 0x0041; }
inline Op BinaryenI64Const() { return 0x0042; }
inline Op BinaryenF32Const() { return 0x0043; }
inline Op BinaryenF64Const() { return 0x0044; }
inline Op BinaryenI32Eqz() { return 0x0045; }
inline Op BinaryenI32Eq() { return 0x0046; }
inline Op BinaryenI32Ne() { return 0x0047; }
inline Op BinaryenI32LtS() { return 0x0048; }
inline Op BinaryenI32LtU() { return 0x0049; }
inline Op BinaryenI32GtS() { return 0x004A; }
inline Op BinaryenI32GtU() { return 0x004B; }
inline Op BinaryenI32LeS() { return 0x004C; }
inline Op BinaryenI32LeU() { return 0x004D; }
inline Op BinaryenI32GeS() { return 0x004E; }
inline Op BinaryenI32GeU() { return 0x004F; }
inline Op BinaryenI64Eqz() { return 0x0050; }
inline Op BinaryenI64Eq() { return 0x0051; }
inline Op BinaryenI64Ne() { return 0x0052; }
inline Op BinaryenI64LtS() { return 0x0053; }
inline Op BinaryenI64LtU() { return 0x0054; }
inline Op BinaryenI64GtS() { return 0x0055; }
inline Op BinaryenI64GtU() { return 0x0056; }
inline Op BinaryenI64LeS() { return 0x0057; }
inline Op BinaryenI64LeU() { return 0x0058; }
inline Op BinaryenI64GeS() { return 0x0059; }
inline Op BinaryenI64GeU() { return 0x005A; }
inline Op BinaryenF32Eq() { return 0x005B; }
inline Op BinaryenF32Ne() { return 0x005C; }
inline Op BinaryenF32Lt() { return 0x005D; }
inline Op BinaryenF32Gt() { return 0x005E; }
inline Op BinaryenF32Le() { return 0x005F; }
inline Op BinaryenF32Ge() { return 0x0060; }
inline Op BinaryenF64Eq() { return 0x0061; }
inline Op BinaryenF64Ne() { return 0x0062; }
inline Op BinaryenF64Lt() { return 0x0063; }
inline Op BinaryenF64Gt() { return 0x0064; }
inline Op BinaryenF64Le() { return 0x0065; }
inline Op BinaryenF64Ge() { return 0x0066; }
inline Op BinaryenI32Clz() { return 0x0067; }
inline Op BinaryenI32Ctz() { return 0x0068; }
inline Op BinaryenI32Popcnt() { return 0x0069; }
inline Op BinaryenI32Add() { return 0x006A; }
inline Op BinaryenI32Sub() { return 0x006B; }
inline Op BinaryenI32Mul() { return 0x006C; }
inline Op BinaryenI32DivS() { return 0x006D; }
inline Op BinaryenI32DivU() { return 0x006E; }
inline Op BinaryenI32RemS() { return 0x006F; }
inline Op BinaryenI32RemU() { return 0x0070; }
inline Op BinaryenI32And() { return 0x0071; }
inline Op BinaryenI32Or() { return 0x0072; }
inline Op BinaryenI32Xor() { return 0x0073; }
inline Op BinaryenI32Shl() { return 0x0074; }
inline Op BinaryenI32ShrS() { return 0x0075; }
inline Op BinaryenI32ShrU() { return 0x0076; }
inline Op BinaryenI32Rotl() { return 0x0077; }
inline Op BinaryenI32Rotr() { return 0x0078; }
inline Op BinaryenI64Clz() { return 0x0079; }
inline Op BinaryenI64Ctz() { return 0x007A; }
inline Op BinaryenI64Popcnt() { return 0x007B; }
inline Op BinaryenI64Add() { return 0x007C; }
inline Op BinaryenI64Sub() { return 0x007D; }
inline Op BinaryenI64Mul() { return 0x007E; }
inline Op BinaryenI64DivS() { return 0x007F; }
inline Op BinaryenI64DivU() { return 0x0080; }
inline Op BinaryenI64RemS() { return 0x0081; }
inline Op BinaryenI64RemU() { return 0x0082; }
inline Op BinaryenI64And() { return 0x0083; }
inline Op BinaryenI64Or() { return 0x0084; }
inline Op BinaryenI64Xor() { return 0x0085; }
inline Op BinaryenI64Shl() { return 0x0086; }
inline Op BinaryenI64ShrS() { return 0x0087; }
inline Op BinaryenI64ShrU() { return 0x0088; }
inline Op BinaryenI64Rotl() { return 0x0089; }
inline Op BinaryenI64Rotr() { return 0x008A; }
inline Op BinaryenF32Abs() { return 0x008B; }
inline Op BinaryenF32Neg() { return 0x008C; }
inline Op BinaryenF32Ceil() { return 0x008D; }
inline Op BinaryenF32Floor() { return 0x008E; }
inline Op BinaryenF32Trunc() { return 0x008F; }
inline Op BinaryenF32Nearest() { return 0x0090; }
inline Op BinaryenF32Sqrt() { return 0x0091; }
inline Op BinaryenF32Add() { return 0x0092; }
inline Op BinaryenF32Sub() { return 0x0093; }
inline Op BinaryenF32Mul() { return 0x0094; }
inline Op BinaryenF32Div() { return 0x0095; }
inline Op BinaryenF32Min() { return 0x0096; }
inline Op BinaryenF32Max() { return 0x0097; }
inline Op BinaryenF32Copysign() { return 0x0098; }
inline Op BinaryenF64Abs() { return 0x0099; }
inline Op BinaryenF64Neg() { return 0x009A; }
inline Op BinaryenF64Ceil() { return 0x009B; }
inline Op BinaryenF64Floor() { return 0x009C; }
inline Op BinaryenF64Trunc() { return 0x009D; }
inline Op BinaryenF64Nearest() { return 0x009E; }
inline Op BinaryenF64Sqrt() { return 0x009F; }
inline Op BinaryenF64Add() { return 0x00A0; }
inline Op BinaryenF64Sub() { return 0x00A1; }
inline Op BinaryenF64Mul() { return 0x00A2; }
inline Op BinaryenF64Div() { return 0x00A3; }
inline Op BinaryenF64Min() { return 0x00A4; }
inline Op BinaryenF64Max() { return 0x00A5; }
inline Op BinaryenF64Copysign() { return 0x00A6; }
inline Op BinaryenI32WrapI64() { return 0x00A7; }
inline Op BinaryenI32TruncF32S() { return 0x00A8; }
inline Op BinaryenI32TruncF32U() { return 0x00A9; }
inline Op BinaryenI32TruncF64S() { return 0x00AA; }
inline Op BinaryenI32TruncF64U() { return 0x00AB; }
inline Op BinaryenI64ExtendI32S() { return 0x00AC; }
inline Op BinaryenI64ExtendI32U() { return 0x00AD; }
inline Op BinaryenI64TruncF32S() { return 0x00AE; }
inline Op BinaryenI64TruncF32U() { return 0x00AF; }
inline Op BinaryenI64TruncF64S() { return 0x00B0; }
inline Op BinaryenI64TruncF64U() { return 0x00B1; }
inline Op BinaryenF32ConvertI32S() { return 0x00B2; }
inline Op BinaryenF32ConvertI32U() { return 0x00B3; }
inline Op BinaryenF32ConvertI64S() { return 0x00B4; }
inline Op BinaryenF32ConvertI64U() { return 0x00B5; }
inline Op BinaryenF32DemoteF64() { return 0x00B6; }
inline Op BinaryenF64ConvertI32S() { return 0x00B7; }
inline Op BinaryenF64ConvertI32U() { return 0x00B8; }
inline Op BinaryenF64ConvertI64S() { return 0x00B9; }
inline Op BinaryenF64ConvertI64U() { return 0x00BA; }
inline Op BinaryenF64PromoteF32() { return 0x00BB; }
inline Op BinaryenI32ReinterpretF32() { return 0x00BC; }
inline Op BinaryenI64ReinterpretF64() { return 0x00BD; }
inline Op BinaryenF32ReinterpretI32() { return 0x00BE; }
inline Op BinaryenF64ReinterpretI64() { return 0x00BF; }
inline Op BinaryenI32Extend8S() { return 0x00C0; }
inline Op BinaryenI32Extend16S() { return 0x00C1; }
inline Op BinaryenI64Extend8S() { return 0x00C2; }
inline Op BinaryenI64Extend16S() { return 0x00C3; }
inline Op BinaryenI64Extend32S() { return 0x00C4; }
// inline Op BinaryenInterpAlloca() { return 0x00E0; }
// inline Op BinaryenInterpBrUnless() { return 0x00E1; }
// inline Op BinaryenInterpCallImport() { return 0x00E2; }
// inline Op BinaryenInterpData() { return 0x00E3; }
// inline Op BinaryenInterpDropKeep() { return 0x00E4; }
// inline Op BinaryenInterpCatchDrop() { return 0x00E5; }
// inline Op BinaryenInterpAdjustFrameForReturnCall() { return 0x00E6; }
inline Op BinaryenI32TruncSatF32S() { return 0xFC00; }
inline Op BinaryenI32TruncSatF32U() { return 0xFC01; }
inline Op BinaryenI32TruncSatF64S() { return 0xFC02; }
inline Op BinaryenI32TruncSatF64U() { return 0xFC03; }
inline Op BinaryenI64TruncSatF32S() { return 0xFC04; }
inline Op BinaryenI64TruncSatF32U() { return 0xFC05; }
inline Op BinaryenI64TruncSatF64S() { return 0xFC06; }
inline Op BinaryenI64TruncSatF64U() { return 0xFC07; }
inline Op BinaryenMemoryInit() { return 0xFC08; }
inline Op BinaryenDataDrop() { return 0xFC09; }
inline Op BinaryenMemoryCopy() { return 0xFC0A; }
inline Op BinaryenMemoryFill() { return 0xFC0B; }
inline Op BinaryenTableInit() { return 0xFC0C; }
inline Op BinaryenElemDrop() { return 0xFC0D; }
inline Op BinaryenTableCopy() { return 0xFC0E; }
inline Op BinaryenTableGet() { return 0x0025; }
inline Op BinaryenTableSet() { return 0x0026; }
inline Op BinaryenTableGrow() { return 0xFC0F; }
inline Op BinaryenTableSize() { return 0xFC10; }
inline Op BinaryenTableFill() { return 0xFC11; }
inline Op BinaryenRefNull() { return 0x00D0; }
inline Op BinaryenRefIsNull() { return 0x00D1; }
inline Op BinaryenRefFunc() { return 0x00D2; }
inline Op BinaryenV128Load() { return 0xFD00; }
inline Op BinaryenV128Load8X8S() { return 0xFD01; }
inline Op BinaryenV128Load8X8U() { return 0xFD02; }
inline Op BinaryenV128Load16X4S() { return 0xFD03; }
inline Op BinaryenV128Load16X4U() { return 0xFD04; }
inline Op BinaryenV128Load32X2S() { return 0xFD05; }
inline Op BinaryenV128Load32X2U() { return 0xFD06; }
inline Op BinaryenV128Load8Splat() { return 0xFD07; }
inline Op BinaryenV128Load16Splat() { return 0xFD08; }
inline Op BinaryenV128Load32Splat() { return 0xFD09; }
inline Op BinaryenV128Load64Splat() { return 0xFD0A; }
inline Op BinaryenV128Store() { return 0xFD0B; }
inline Op BinaryenV128Const() { return 0xFD0C; }
inline Op BinaryenI8X16Shuffle() { return 0xFD0D; }
inline Op BinaryenI8X16Swizzle() { return 0xFD0E; }
inline Op BinaryenI8X16Splat() { return 0xFD0F; }
inline Op BinaryenI16X8Splat() { return 0xFD10; }
inline Op BinaryenI32X4Splat() { return 0xFD11; }
inline Op BinaryenI64X2Splat() { return 0xFD12; }
inline Op BinaryenF32X4Splat() { return 0xFD13; }
inline Op BinaryenF64X2Splat() { return 0xFD14; }
inline Op BinaryenI8X16ExtractLaneS() { return 0xFD15; }
inline Op BinaryenI8X16ExtractLaneU() { return 0xFD16; }
inline Op BinaryenI8X16ReplaceLane() { return 0xFD17; }
inline Op BinaryenI16X8ExtractLaneS() { return 0xFD18; }
inline Op BinaryenI16X8ExtractLaneU() { return 0xFD19; }
inline Op BinaryenI16X8ReplaceLane() { return 0xFD1A; }
inline Op BinaryenI32X4ExtractLane() { return 0xFD1B; }
inline Op BinaryenI32X4ReplaceLane() { return 0xFD1C; }
inline Op BinaryenI64X2ExtractLane() { return 0xFD1D; }
inline Op BinaryenI64X2ReplaceLane() { return 0xFD1E; }
inline Op BinaryenF32X4ExtractLane() { return 0xFD1F; }
inline Op BinaryenF32X4ReplaceLane() { return 0xFD20; }
inline Op BinaryenF64X2ExtractLane() { return 0xFD21; }
inline Op BinaryenF64X2ReplaceLane() { return 0xFD22; }
inline Op BinaryenI8X16Eq() { return 0xFD23; }
inline Op BinaryenI8X16Ne() { return 0xFD24; }
inline Op BinaryenI8X16LtS() { return 0xFD25; }
inline Op BinaryenI8X16LtU() { return 0xFD26; }
inline Op BinaryenI8X16GtS() { return 0xFD27; }
inline Op BinaryenI8X16GtU() { return 0xFD28; }
inline Op BinaryenI8X16LeS() { return 0xFD29; }
inline Op BinaryenI8X16LeU() { return 0xFD2A; }
inline Op BinaryenI8X16GeS() { return 0xFD2B; }
inline Op BinaryenI8X16GeU() { return 0xFD2C; }
inline Op BinaryenI16X8Eq() { return 0xFD2D; }
inline Op BinaryenI16X8Ne() { return 0xFD2E; }
inline Op BinaryenI16X8LtS() { return 0xFD2F; }
inline Op BinaryenI16X8LtU() { return 0xFD30; }
inline Op BinaryenI16X8GtS() { return 0xFD31; }
inline Op BinaryenI16X8GtU() { return 0xFD32; }
inline Op BinaryenI16X8LeS() { return 0xFD33; }
inline Op BinaryenI16X8LeU() { return 0xFD34; }
inline Op BinaryenI16X8GeS() { return 0xFD35; }
inline Op BinaryenI16X8GeU() { return 0xFD36; }
inline Op BinaryenI32X4Eq() { return 0xFD37; }
inline Op BinaryenI32X4Ne() { return 0xFD38; }
inline Op BinaryenI32X4LtS() { return 0xFD39; }
inline Op BinaryenI32X4LtU() { return 0xFD3A; }
inline Op BinaryenI32X4GtS() { return 0xFD3B; }
inline Op BinaryenI32X4GtU() { return 0xFD3C; }
inline Op BinaryenI32X4LeS() { return 0xFD3D; }
inline Op BinaryenI32X4LeU() { return 0xFD3E; }
inline Op BinaryenI32X4GeS() { return 0xFD3F; }
inline Op BinaryenI32X4GeU() { return 0xFD40; }
inline Op BinaryenF32X4Eq() { return 0xFD41; }
inline Op BinaryenF32X4Ne() { return 0xFD42; }
inline Op BinaryenF32X4Lt() { return 0xFD43; }
inline Op BinaryenF32X4Gt() { return 0xFD44; }
inline Op BinaryenF32X4Le() { return 0xFD45; }
inline Op BinaryenF32X4Ge() { return 0xFD46; }
inline Op BinaryenF64X2Eq() { return 0xFD47; }
inline Op BinaryenF64X2Ne() { return 0xFD48; }
inline Op BinaryenF64X2Lt() { return 0xFD49; }
inline Op BinaryenF64X2Gt() { return 0xFD4A; }
inline Op BinaryenF64X2Le() { return 0xFD4B; }
inline Op BinaryenF64X2Ge() { return 0xFD4C; }
inline Op BinaryenV128Not() { return 0xFD4D; }
inline Op BinaryenV128And() { return 0xFD4E; }
inline Op BinaryenV128Andnot() { return 0xFD4F; }
inline Op BinaryenV128Or() { return 0xFD50; }
inline Op BinaryenV128Xor() { return 0xFD51; }
inline Op BinaryenV128BitSelect() { return 0xFD52; }
inline Op BinaryenV128AnyTrue() { return 0xFD53; }
inline Op BinaryenV128Load8Lane() { return 0xFD54; }
inline Op BinaryenV128Load16Lane() { return 0xFD55; }
inline Op BinaryenV128Load32Lane() { return 0xFD56; }
inline Op BinaryenV128Load64Lane() { return 0xFD57; }
inline Op BinaryenV128Store8Lane() { return 0xFD58; }
inline Op BinaryenV128Store16Lane() { return 0xFD59; }
inline Op BinaryenV128Store32Lane() { return 0xFD5A; }
inline Op BinaryenV128Store64Lane() { return 0xFD5B; }
inline Op BinaryenV128Load32Zero() { return 0xFD5C; }
inline Op BinaryenV128Load64Zero() { return 0xFD5D; }
inline Op BinaryenF32X4DemoteF64X2Zero() { return 0xFD5E; }
inline Op BinaryenF64X2PromoteLowF32X4() { return 0xFD5F; }
inline Op BinaryenI8X16Abs() { return 0xFD60; }
inline Op BinaryenI8X16Neg() { return 0xFD61; }
inline Op BinaryenI8X16Popcnt() { return 0xFD62; }
inline Op BinaryenI8X16AllTrue() { return 0xFD63; }
inline Op BinaryenI8X16Bitmask() { return 0xFD64; }
inline Op BinaryenI8X16NarrowI16X8S() { return 0xFD65; }
inline Op BinaryenI8X16NarrowI16X8U() { return 0xFD66; }
inline Op BinaryenI8X16Shl() { return 0xFD6B; }
inline Op BinaryenI8X16ShrS() { return 0xFD6C; }
inline Op BinaryenI8X16ShrU() { return 0xFD6D; }
inline Op BinaryenI8X16Add() { return 0xFD6E; }
inline Op BinaryenI8X16AddSatS() { return 0xFD6F; }
inline Op BinaryenI8X16AddSatU() { return 0xFD70; }
inline Op BinaryenI8X16Sub() { return 0xFD71; }
inline Op BinaryenI8X16SubSatS() { return 0xFD72; }
inline Op BinaryenI8X16SubSatU() { return 0xFD73; }
inline Op BinaryenI8X16MinS() { return 0xFD76; }
inline Op BinaryenI8X16MinU() { return 0xFD77; }
inline Op BinaryenI8X16MaxS() { return 0xFD78; }
inline Op BinaryenI8X16MaxU() { return 0xFD79; }
inline Op BinaryenI8X16AvgrU() { return 0xFD7B; }
inline Op BinaryenI16X8ExtaddPairwiseI8X16S() { return 0xFD7C; }
inline Op BinaryenI16X8ExtaddPairwiseI8X16U() { return 0xFD7D; }
inline Op BinaryenI32X4ExtaddPairwiseI16X8S() { return 0xFD7E; }
inline Op BinaryenI32X4ExtaddPairwiseI16X8U() { return 0xFD7F; }
inline Op BinaryenI16X8Abs() { return 0xFD80; }
inline Op BinaryenI16X8Neg() { return 0xFD81; }
inline Op BinaryenI16X8Q15mulrSatS() { return 0xFD82; }
inline Op BinaryenI16X8AllTrue() { return 0xFD83; }
inline Op BinaryenI16X8Bitmask() { return 0xFD84; }
inline Op BinaryenI16X8NarrowI32X4S() { return 0xFD85; }
inline Op BinaryenI16X8NarrowI32X4U() { return 0xFD86; }
inline Op BinaryenI16X8ExtendLowI8X16S() { return 0xFD87; }
inline Op BinaryenI16X8ExtendHighI8X16S() { return 0xFD88; }
inline Op BinaryenI16X8ExtendLowI8X16U() { return 0xFD89; }
inline Op BinaryenI16X8ExtendHighI8X16U() { return 0xFD8A; }
inline Op BinaryenI16X8Shl() { return 0xFD8B; }
inline Op BinaryenI16X8ShrS() { return 0xFD8C; }
inline Op BinaryenI16X8ShrU() { return 0xFD8D; }
inline Op BinaryenI16X8Add() { return 0xFD8E; }
inline Op BinaryenI16X8AddSatS() { return 0xFD8F; }
inline Op BinaryenI16X8AddSatU() { return 0xFD90; }
inline Op BinaryenI16X8Sub() { return 0xFD91; }
inline Op BinaryenI16X8SubSatS() { return 0xFD92; }
inline Op BinaryenI16X8SubSatU() { return 0xFD93; }
inline Op BinaryenI16X8Mul() { return 0xFD95; }
inline Op BinaryenI16X8MinS() { return 0xFD96; }
inline Op BinaryenI16X8MinU() { return 0xFD97; }
inline Op BinaryenI16X8MaxS() { return 0xFD98; }
inline Op BinaryenI16X8MaxU() { return 0xFD99; }
inline Op BinaryenI16X8AvgrU() { return 0xFD9B; }
inline Op BinaryenI16X8ExtmulLowI8X16S() { return 0xFD9C; }
inline Op BinaryenI16X8ExtmulHighI8X16S() { return 0xFD9D; }
inline Op BinaryenI16X8ExtmulLowI8X16U() { return 0xFD9E; }
inline Op BinaryenI16X8ExtmulHighI8X16U() { return 0xFD9F; }
inline Op BinaryenI32X4Abs() { return 0xFDA0; }
inline Op BinaryenI32X4Neg() { return 0xFDA1; }
inline Op BinaryenI32X4AllTrue() { return 0xFDA3; }
inline Op BinaryenI32X4Bitmask() { return 0xFDA4; }
inline Op BinaryenI32X4ExtendLowI16X8S() { return 0xFDA7; }
inline Op BinaryenI32X4ExtendHighI16X8S() { return 0xFDA8; }
inline Op BinaryenI32X4ExtendLowI16X8U() { return 0xFDA9; }
inline Op BinaryenI32X4ExtendHighI16X8U() { return 0xFDAA; }
inline Op BinaryenI32X4Shl() { return 0xFDAB; }
inline Op BinaryenI32X4ShrS() { return 0xFDAC; }
inline Op BinaryenI32X4ShrU() { return 0xFDAD; }
inline Op BinaryenI32X4Add() { return 0xFDAE; }
inline Op BinaryenI32X4Sub() { return 0xFDB1; }
inline Op BinaryenI32X4Mul() { return 0xFDB5; }
inline Op BinaryenI32X4MinS() { return 0xFDB6; }
inline Op BinaryenI32X4MinU() { return 0xFDB7; }
inline Op BinaryenI32X4MaxS() { return 0xFDB8; }
inline Op BinaryenI32X4MaxU() { return 0xFDB9; }
inline Op BinaryenI32X4DotI16X8S() { return 0xFDBA; }
inline Op BinaryenI32X4ExtmulLowI16X8S() { return 0xFDBC; }
inline Op BinaryenI32X4ExtmulHighI16X8S() { return 0xFDBD; }
inline Op BinaryenI32X4ExtmulLowI16X8U() { return 0xFDBE; }
inline Op BinaryenI32X4ExtmulHighI16X8U() { return 0xFDBF; }
inline Op BinaryenI64X2Abs() { return 0xFDC0; }
inline Op BinaryenI64X2Neg() { return 0xFDC1; }
inline Op BinaryenI64X2AllTrue() { return 0xFDC3; }
inline Op BinaryenI64X2Bitmask() { return 0xFDC4; }
inline Op BinaryenI64X2ExtendLowI32X4S() { return 0xFDC7; }
inline Op BinaryenI64X2ExtendHighI32X4S() { return 0xFDC8; }
inline Op BinaryenI64X2ExtendLowI32X4U() { return 0xFDC9; }
inline Op BinaryenI64X2ExtendHighI32X4U() { return 0xFDCA; }
inline Op BinaryenI64X2Shl() { return 0xFDCB; }
inline Op BinaryenI64X2ShrS() { return 0xFDCC; }
inline Op BinaryenI64X2ShrU() { return 0xFDCD; }
inline Op BinaryenI64X2Add() { return 0xFDCE; }
inline Op BinaryenI64X2Sub() { return 0xFDD1; }
inline Op BinaryenI64X2Mul() { return 0xFDD5; }
inline Op BinaryenI64X2Eq() { return 0xFDD6; }
inline Op BinaryenI64X2Ne() { return 0xFDD7; }
inline Op BinaryenI64X2LtS() { return 0xFDD8; }
inline Op BinaryenI64X2GtS() { return 0xFDD9; }
inline Op BinaryenI64X2LeS() { return 0xFDDA; }
inline Op BinaryenI64X2GeS() { return 0xFDDB; }
inline Op BinaryenI64X2ExtmulLowI32X4S() { return 0xFDDC; }
inline Op BinaryenI64X2ExtmulHighI32X4S() { return 0xFDDD; }
inline Op BinaryenI64X2ExtmulLowI32X4U() { return 0xFDDE; }
inline Op BinaryenI64X2ExtmulHighI32X4U() { return 0xFDDF; }
inline Op BinaryenF32X4Ceil() { return 0xFD67; }
inline Op BinaryenF32X4Floor() { return 0xFD68; }
inline Op BinaryenF32X4Trunc() { return 0xFD69; }
inline Op BinaryenF32X4Nearest() { return 0xFD6A; }
inline Op BinaryenF64X2Ceil() { return 0xFD74; }
inline Op BinaryenF64X2Floor() { return 0xFD75; }
inline Op BinaryenF64X2Trunc() { return 0xFD7A; }
inline Op BinaryenF64X2Nearest() { return 0xFD94; }
inline Op BinaryenF32X4Abs() { return 0xFDE0; }
inline Op BinaryenF32X4Neg() { return 0xFDE1; }
inline Op BinaryenF32X4Sqrt() { return 0xFDE3; }
inline Op BinaryenF32X4Add() { return 0xFDE4; }
inline Op BinaryenF32X4Sub() { return 0xFDE5; }
inline Op BinaryenF32X4Mul() { return 0xFDE6; }
inline Op BinaryenF32X4Div() { return 0xFDE7; }
inline Op BinaryenF32X4Min() { return 0xFDE8; }
inline Op BinaryenF32X4Max() { return 0xFDE9; }
inline Op BinaryenF32X4PMin() { return 0xFDEA; }
inline Op BinaryenF32X4PMax() { return 0xFDEB; }
inline Op BinaryenF64X2Abs() { return 0xFDEC; }
inline Op BinaryenF64X2Neg() { return 0xFDED; }
inline Op BinaryenF64X2Sqrt() { return 0xFDEF; }
inline Op BinaryenF64X2Add() { return 0xFDF0; }
inline Op BinaryenF64X2Sub() { return 0xFDF1; }
inline Op BinaryenF64X2Mul() { return 0xFDF2; }
inline Op BinaryenF64X2Div() { return 0xFDF3; }
inline Op BinaryenF64X2Min() { return 0xFDF4; }
inline Op BinaryenF64X2Max() { return 0xFDF5; }
inline Op BinaryenF64X2PMin() { return 0xFDF6; }
inline Op BinaryenF64X2PMax() { return 0xFDF7; }
inline Op BinaryenI32X4TruncSatF32X4S() { return 0xFDF8; }
inline Op BinaryenI32X4TruncSatF32X4U() { return 0xFDF9; }
inline Op BinaryenF32X4ConvertI32X4S() { return 0xFDFA; }
inline Op BinaryenF32X4ConvertI32X4U() { return 0xFDFB; }
inline Op BinaryenI32X4TruncSatF64X2SZero() { return 0xFDFC; }
inline Op BinaryenI32X4TruncSatF64X2UZero() { return 0xFDFD; }
inline Op BinaryenF64X2ConvertLowI32X4S() { return 0xFDFE; }
inline Op BinaryenF64X2ConvertLowI32X4U() { return 0xFDFF; }
// inline Op BinaryenI8X16RelaxedSwizzle() { return 0xFD00; }
// inline Op BinaryenI32X4RelaxedTruncF32X4S() { return 0xFD01; }
// inline Op BinaryenI32X4RelaxedTruncF32X4U() { return 0xFD02; }
// inline Op BinaryenI32X4RelaxedTruncF64X2SZero() { return 0xFD03; }
// inline Op BinaryenI32X4RelaxedTruncF64X2UZero() { return 0xFD04; }
// inline Op BinaryenF32X4RelaxedMadd() { return 0xFD05; }
// inline Op BinaryenF32X4RelaxedNmadd() { return 0xFD06; }
// inline Op BinaryenF64X2RelaxedMadd() { return 0xFD07; }
// inline Op BinaryenF64X2RelaxedNmadd() { return 0xFD08; }
// inline Op BinaryenI8X16RelaxedLaneSelect() { return 0xFD09; }
// inline Op BinaryenI16X8RelaxedLaneSelect() { return 0xFD0A; }
// inline Op BinaryenI32X4RelaxedLaneSelect() { return 0xFD0B; }
// inline Op BinaryenI64X2RelaxedLaneSelect() { return 0xFD0C; }
// inline Op BinaryenF32X4RelaxedMin() { return 0xFD0D; }
// inline Op BinaryenF32X4RelaxedMax() { return 0xFD0E; }
// inline Op BinaryenF64X2RelaxedMin() { return 0xFD0F; }
// inline Op BinaryenF64X2RelaxedMax() { return 0xFD10; }
// inline Op BinaryenI16X8RelaxedQ15mulrS() { return 0xFD11; }
inline Op BinaryenI16X8DotI8X16I7X16S() { return 0xFD12; }
inline Op BinaryenI32X4DotI8X16I7X16AddS() { return 0xFD13; }
inline Op BinaryenMemoryAtomicNotify() { return 0xFE00; }
inline Op BinaryenMemoryAtomicWait32() { return 0xFE01; }
inline Op BinaryenMemoryAtomicWait64() { return 0xFE02; }
inline Op BinaryenAtomicFence() { return 0xFE03; }
inline Op BinaryenI32AtomicLoad() { return 0xFE10; }
inline Op BinaryenI64AtomicLoad() { return 0xFE11; }
inline Op BinaryenI32AtomicLoad8U() { return 0xFE12; }
inline Op BinaryenI32AtomicLoad16U() { return 0xFE13; }
inline Op BinaryenI64AtomicLoad8U() { return 0xFE14; }
inline Op BinaryenI64AtomicLoad16U() { return 0xFE15; }
inline Op BinaryenI64AtomicLoad32U() { return 0xFE16; }
inline Op BinaryenI32AtomicStore() { return 0xFE17; }
inline Op BinaryenI64AtomicStore() { return 0xFE18; }
inline Op BinaryenI32AtomicStore8() { return 0xFE19; }
inline Op BinaryenI32AtomicStore16() { return 0xFE1A; }
inline Op BinaryenI64AtomicStore8() { return 0xFE1B; }
inline Op BinaryenI64AtomicStore16() { return 0xFE1C; }
inline Op BinaryenI64AtomicStore32() { return 0xFE1D; }
inline Op BinaryenI32AtomicRmwAdd() { return 0xFE1E; }
inline Op BinaryenI64AtomicRmwAdd() { return 0xFE1F; }
inline Op BinaryenI32AtomicRmw8AddU() { return 0xFE20; }
inline Op BinaryenI32AtomicRmw16AddU() { return 0xFE21; }
inline Op BinaryenI64AtomicRmw8AddU() { return 0xFE22; }
inline Op BinaryenI64AtomicRmw16AddU() { return 0xFE23; }
inline Op BinaryenI64AtomicRmw32AddU() { return 0xFE24; }
inline Op BinaryenI32AtomicRmwSub() { return 0xFE25; }
inline Op BinaryenI64AtomicRmwSub() { return 0xFE26; }
inline Op BinaryenI32AtomicRmw8SubU() { return 0xFE27; }
inline Op BinaryenI32AtomicRmw16SubU() { return 0xFE28; }
inline Op BinaryenI64AtomicRmw8SubU() { return 0xFE29; }
inline Op BinaryenI64AtomicRmw16SubU() { return 0xFE2A; }
inline Op BinaryenI64AtomicRmw32SubU() { return 0xFE2B; }
inline Op BinaryenI32AtomicRmwAnd() { return 0xFE2C; }
inline Op BinaryenI64AtomicRmwAnd() { return 0xFE2D; }
inline Op BinaryenI32AtomicRmw8AndU() { return 0xFE2E; }
inline Op BinaryenI32AtomicRmw16AndU() { return 0xFE2F; }
inline Op BinaryenI64AtomicRmw8AndU() { return 0xFE30; }
inline Op BinaryenI64AtomicRmw16AndU() { return 0xFE31; }
inline Op BinaryenI64AtomicRmw32AndU() { return 0xFE32; }
inline Op BinaryenI32AtomicRmwOr() { return 0xFE33; }
inline Op BinaryenI64AtomicRmwOr() { return 0xFE34; }
inline Op BinaryenI32AtomicRmw8OrU() { return 0xFE35; }
inline Op BinaryenI32AtomicRmw16OrU() { return 0xFE36; }
inline Op BinaryenI64AtomicRmw8OrU() { return 0xFE37; }
inline Op BinaryenI64AtomicRmw16OrU() { return 0xFE38; }
inline Op BinaryenI64AtomicRmw32OrU() { return 0xFE39; }
inline Op BinaryenI32AtomicRmwXor() { return 0xFE3A; }
inline Op BinaryenI64AtomicRmwXor() { return 0xFE3B; }
inline Op BinaryenI32AtomicRmw8XorU() { return 0xFE3C; }
inline Op BinaryenI32AtomicRmw16XorU() { return 0xFE3D; }
inline Op BinaryenI64AtomicRmw8XorU() { return 0xFE3E; }
inline Op BinaryenI64AtomicRmw16XorU() { return 0xFE3F; }
inline Op BinaryenI64AtomicRmw32XorU() { return 0xFE40; }
inline Op BinaryenI32AtomicRmwXchg() { return 0xFE41; }
inline Op BinaryenI64AtomicRmwXchg() { return 0xFE42; }
inline Op BinaryenI32AtomicRmw8XchgU() { return 0xFE43; }
inline Op BinaryenI32AtomicRmw16XchgU() { return 0xFE44; }
inline Op BinaryenI64AtomicRmw8XchgU() { return 0xFE45; }
inline Op BinaryenI64AtomicRmw16XchgU() { return 0xFE46; }
inline Op BinaryenI64AtomicRmw32XchgU() { return 0xFE47; }
inline Op BinaryenI32AtomicRmwCmpxchg() { return 0xFE48; }
inline Op BinaryenI64AtomicRmwCmpxchg() { return 0xFE49; }
inline Op BinaryenI32AtomicRmw8CmpxchgU() { return 0xFE4A; }
inline Op BinaryenI32AtomicRmw16CmpxchgU() { return 0xFE4B; }
inline Op BinaryenI64AtomicRmw8CmpxchgU() { return 0xFE4C; }
inline Op BinaryenI64AtomicRmw16CmpxchgU() { return 0xFE4D; }
inline Op BinaryenI64AtomicRmw32CmpxchgU() { return 0xFE4E; }
inline Op BinaryenMoveI32() { return 0x00E7; }
inline Op BinaryenMoveF32() { return 0x00E8; }
inline Op BinaryenMoveI64() { return 0x00E9; }
inline Op BinaryenMoveF64() { return 0x00EA; }
inline Op BinaryenMoveV128() { return 0x00EB; }
inline Op BinaryenConst32() { return 0x00EC; }
inline Op BinaryenConst64() { return 0x00ED; }

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
inline Op getReplacementForOp(Op opcode, std::mt19937& rng)
{
    static bool init = false;
    static std::vector<Op>
        i32Arith, i32Bits, i32Cmp, i32Unary,
        i64Arith, i64Bits, i64Cmp, i64Unary,
        f32Arith, f32Cmp,  f32Unary,
        f64Arith, f64Cmp,  f64Unary,
        i8Arith ,i8Shift,i8Cmp ,i8Unary ,
        i16Arith,i16Shift,i16Cmp,i16Unary,
        i32xArith,i32xShift,i32xCmp,i32xUnary,
        i64xArith,i64xShift,i64xCmp,i64xUnary,
        f32xArith,f32xCmp ,f32xUnary,
        f64xArith,f64xCmp ,f64xUnary,
        v128Logic,
        ctrlFlow, localGlobal, memoryOps, constOps, conversion, tableOps, refOps, atomicOps,
        directCalls, bulkMemoryOps, saturatingTrunc, simdConvert, moveConst, simdNarrow, simdLaneAccess, simdLaneLoadStore, simdMemoryOps, simdSplatShuffle;

        if (!init) {
   
            /*──────────── scalar i32 ────────────*/
            i32Arith = { BinaryenI32Add(), BinaryenI32Sub(), BinaryenI32Mul(),
                         BinaryenI32DivS(), BinaryenI32DivU(),
                         BinaryenI32RemS(), BinaryenI32RemU() };
            i32Bits  = { BinaryenI32And(), BinaryenI32Or(),  BinaryenI32Xor(),
                         BinaryenI32Shl(), BinaryenI32ShrS(), BinaryenI32ShrU(),
                         BinaryenI32Rotl(), BinaryenI32Rotr() };
            i32Cmp   = { BinaryenI32Eq(),  BinaryenI32Ne(),
                         BinaryenI32LtS(), BinaryenI32LtU(), BinaryenI32LeS(), BinaryenI32LeU(),
                         BinaryenI32GtS(), BinaryenI32GtU(), BinaryenI32GeS(), BinaryenI32GeU() };
            i32Unary = { BinaryenI32Clz(), BinaryenI32Ctz(), BinaryenI32Popcnt(), BinaryenI32Eqz() };
    
            /*──────────── scalar i64 ────────────*/
            i64Arith = { BinaryenI64Add(), BinaryenI64Sub(), BinaryenI64Mul(),
                         BinaryenI64DivS(), BinaryenI64DivU(),
                         BinaryenI64RemS(), BinaryenI64RemU() };
            i64Bits  = { BinaryenI64And(), BinaryenI64Or(),  BinaryenI64Xor(),
                         BinaryenI64Shl(), BinaryenI64ShrS(), BinaryenI64ShrU(),
                         BinaryenI64Rotl(), BinaryenI64Rotr() };
            i64Cmp   = { BinaryenI64Eq(),  BinaryenI64Ne(),
                         BinaryenI64LtS(), BinaryenI64LtU(), BinaryenI64LeS(), BinaryenI64LeU(),
                         BinaryenI64GtS(), BinaryenI64GtU(), BinaryenI64GeS(), BinaryenI64GeU() };
            i64Unary = { BinaryenI64Clz(), BinaryenI64Ctz(), BinaryenI64Popcnt() };
    
            /*──────────── scalar f32 / f64 ──────*/
            f32Arith = { BinaryenF32Add(), BinaryenF32Sub(), BinaryenF32Mul(), BinaryenF32Div(),
                         BinaryenF32Min(), BinaryenF32Max(), BinaryenF32Copysign() }; 
            f32Cmp   = { BinaryenF32Eq(),  BinaryenF32Ne(),
                         BinaryenF32Lt(),  BinaryenF32Le(), BinaryenF32Gt(),  BinaryenF32Ge() };
            f32Unary = { BinaryenF32Abs(), BinaryenF32Neg(), BinaryenF32Ceil(),   BinaryenF32Floor(),
                         BinaryenF32Trunc(),BinaryenF32Nearest(), BinaryenF32Sqrt() };
    
            f64Arith = { BinaryenF64Add(), BinaryenF64Sub(), BinaryenF64Mul(), BinaryenF64Div(),
                         BinaryenF64Min(), BinaryenF64Max(), BinaryenF64Copysign() }; 
            f64Cmp   = { BinaryenF64Eq(),  BinaryenF64Ne(),
                         BinaryenF64Lt(),  BinaryenF64Le(), BinaryenF64Gt(),  BinaryenF64Ge() };
            f64Unary = { BinaryenF64Abs(), BinaryenF64Neg(), BinaryenF64Ceil(),   BinaryenF64Floor(),
                         BinaryenF64Trunc(),BinaryenF64Nearest(), BinaryenF64Sqrt() };
    
            /*──────────── v128 logic ────────────*/
            v128Logic = { BinaryenV128And(), BinaryenV128Or(),  BinaryenV128Xor(),
                          BinaryenV128Andnot(), BinaryenV128BitSelect() };
    
            /*──────────── i8x16 ────────────────*/
            i8Arith = { BinaryenI8X16Add(), BinaryenI8X16Sub(),
                        BinaryenI8X16AddSatS(), BinaryenI8X16AddSatU(),
                        BinaryenI8X16SubSatS(), BinaryenI8X16SubSatU(),
                        BinaryenI8X16MinS(),    BinaryenI8X16MinU(),
                        BinaryenI8X16MaxS(),    BinaryenI8X16MaxU(),
                        BinaryenI8X16AvgrU() };
            i8Shift = { BinaryenI8X16Shl(), BinaryenI8X16ShrS(), BinaryenI8X16ShrU() };
            i8Cmp   = { BinaryenI8X16Eq(),  BinaryenI8X16Ne(),  BinaryenI8X16LtS(), BinaryenI8X16LtU(),
                        BinaryenI8X16GtS(), BinaryenI8X16GtU(), BinaryenI8X16LeS(), BinaryenI8X16LeU(),
                        BinaryenI8X16GeS(), BinaryenI8X16GeU() };
            i8Unary = { BinaryenI8X16Abs(), BinaryenI8X16Neg(), BinaryenI8X16AnyTrue(),
                        BinaryenI8X16AllTrue(), BinaryenI8X16Bitmask(), BinaryenI8X16Popcnt() };
    
            /*──────────── i16x8 ────────────────*/
            i16Arith = { BinaryenI16X8Add(), BinaryenI16X8Sub(), BinaryenI16X8Mul(),
                         BinaryenI16X8AddSatS(), BinaryenI16X8AddSatU(),
                         BinaryenI16X8SubSatS(), BinaryenI16X8SubSatU(),
                         BinaryenI16X8MinS(),    BinaryenI16X8MinU(),
                         BinaryenI16X8MaxS(),    BinaryenI16X8MaxU(),
                         BinaryenI16X8AvgrU(),   BinaryenI16X8Q15mulrSatS() };       
            i16Shift = { BinaryenI16X8Shl(), BinaryenI16X8ShrS(), BinaryenI16X8ShrU() };
            i16Cmp   = { BinaryenI16X8Eq(),  BinaryenI16X8Ne(),  BinaryenI16X8LtS(), BinaryenI16X8LtU(),
                         BinaryenI16X8GtS(), BinaryenI16X8GtU(), BinaryenI16X8LeS(), BinaryenI16X8LeU(),
                         BinaryenI16X8GeS(), BinaryenI16X8GeU() };
            i16Unary = { BinaryenI16X8Abs(), BinaryenI16X8Neg(), BinaryenI16X8AnyTrue(),
                         BinaryenI16X8AllTrue(), BinaryenI16X8Bitmask() };
    
            /*──────────── i32x4 ────────────────*/
            i32xArith = { BinaryenI32X4Add(), BinaryenI32X4Sub(), BinaryenI32X4Mul(),
                          BinaryenI32X4MinS(), BinaryenI32X4MinU(),
                          BinaryenI32X4MaxS(), BinaryenI32X4MaxU(),
                          BinaryenI32X4DotI16X8S() };
            i32xShift = { BinaryenI32X4Shl(), BinaryenI32X4ShrS(), BinaryenI32X4ShrU() };
            i32xCmp   = { BinaryenI32X4Eq(),  BinaryenI32X4Ne(),  BinaryenI32X4LtS(), BinaryenI32X4LtU(),
                          BinaryenI32X4GtS(), BinaryenI32X4GtU(), BinaryenI32X4LeS(), BinaryenI32X4LeU(),
                          BinaryenI32X4GeS(), BinaryenI32X4GeU() };
            i32xUnary = { BinaryenI32X4Abs(), BinaryenI32X4Neg(), BinaryenI32X4AnyTrue(),
                          BinaryenI32X4AllTrue(), BinaryenI32X4Bitmask() };
    
            /*──────────── i64x2 ────────────────*/
            i64xArith = { BinaryenI64X2Add(), BinaryenI64X2Sub(), BinaryenI64X2Mul() };
            i64xShift = { BinaryenI64X2Shl(), BinaryenI64X2ShrS(), BinaryenI64X2ShrU() };
            i64xCmp   = { BinaryenI64X2Eq(),  BinaryenI64X2Ne(),  BinaryenI64X2LtS(),
                          BinaryenI64X2GtS(), BinaryenI64X2LeS(), BinaryenI64X2GeS() };
            i64xUnary = { BinaryenI64X2Abs(), BinaryenI64X2Neg(), BinaryenI64X2AnyTrue(),
                          BinaryenI64X2AllTrue(), BinaryenI64X2Bitmask() };
    
            /*──────────── f32x4 / f64x2 ────────*/
            f32xArith = { BinaryenF32X4Add(), BinaryenF32X4Sub(), BinaryenF32X4Mul(),
                          BinaryenF32X4Div(), BinaryenF32X4Min(), BinaryenF32X4Max(),
                          BinaryenF32X4PMin(),BinaryenF32X4PMax() };
            f32xCmp   = { BinaryenF32X4Eq(),  BinaryenF32X4Ne(), BinaryenF32X4Lt(), BinaryenF32X4Gt(),
                          BinaryenF32X4Le(),  BinaryenF32X4Ge() };
            f32xUnary = { BinaryenF32X4Abs(), BinaryenF32X4Neg(), BinaryenF32X4Sqrt(),   BinaryenF32X4Ceil(),   BinaryenF32X4Floor(), BinaryenF32X4Trunc(),  BinaryenF32X4Nearest()};
    
            f64xArith = { BinaryenF64X2Add(), BinaryenF64X2Sub(), BinaryenF64X2Mul(),
                          BinaryenF64X2Div(), BinaryenF64X2Min(), BinaryenF64X2Max(),
                          BinaryenF64X2PMin(),BinaryenF64X2PMax() };
            f64xCmp   = { BinaryenF64X2Eq(),  BinaryenF64X2Ne(), BinaryenF64X2Lt(), BinaryenF64X2Gt(),
                          BinaryenF64X2Le(),  BinaryenF64X2Ge() };
            f64xUnary = { BinaryenF64X2Abs(), BinaryenF64X2Neg(), BinaryenF64X2Sqrt(), BinaryenF64X2Ceil(),   BinaryenF64X2Floor(), BinaryenF64X2Trunc(),  BinaryenF64X2Nearest() };

            simdNarrow = { BinaryenI8X16NarrowI16X8S(), BinaryenI8X16NarrowI16X8U() };

            simdLaneLoadStore = { BinaryenV128Load8Lane(), BinaryenV128Load16Lane(), BinaryenV128Load32Lane(),BinaryenV128Load64Lane(), BinaryenV128Store8Lane(),BinaryenV128Store16Lane(), BinaryenV128Store32Lane(),BinaryenV128Store64Lane() };

            simdSplatShuffle = { BinaryenI8X16Shuffle(), BinaryenI8X16Swizzle(), BinaryenI8X16Splat(), BinaryenI16X8Splat(), BinaryenI32X4Splat(), BinaryenI64X2Splat(), BinaryenF32X4Splat(), BinaryenF64X2Splat() };

            simdMemoryOps = {
                // full‐vector loads
                BinaryenV128Load(),
                BinaryenV128Load8X8S(), BinaryenV128Load8X8U(),
                BinaryenV128Load16X4S(), BinaryenV128Load16X4U(),
                BinaryenV128Load32X2S(), BinaryenV128Load32X2U(),

                BinaryenV128Load8Splat(), BinaryenV128Load16Splat(),
                BinaryenV128Load32Splat(), BinaryenV128Load64Splat(),
                // zero‐extend loads
                BinaryenV128Load32Zero(), BinaryenV128Load64Zero(),
                // full‐vector store
                BinaryenV128Store()
              };

            simdLaneAccess = { BinaryenI8X16ExtractLaneS(), BinaryenI8X16ExtractLaneU(), BinaryenI8X16ReplaceLane(), BinaryenI16X8ExtractLaneS(), BinaryenI16X8ExtractLaneU(), BinaryenI16X8ReplaceLane(), BinaryenI32X4ExtractLane(),
                               BinaryenI32X4ReplaceLane(), BinaryenI64X2ExtractLane(), BinaryenI64X2ReplaceLane(), BinaryenF32X4ExtractLane(), BinaryenF32X4ReplaceLane(), BinaryenF64X2ExtractLane(), BinaryenF64X2ReplaceLane() };

            /*──────────── control flow ────────────*/
            ctrlFlow = { BinaryenUnreachable(), BinaryenNop(), BinaryenBlock(), BinaryenLoop(),
                         BinaryenIf(), BinaryenElse(), BinaryenBr(), BinaryenBrIf(),
                         BinaryenBrTable(), BinaryenReturn(), BinaryenDrop(), BinaryenSelect(),
                         BinaryenSelectT(), BinaryenTry(), BinaryenCatch(), BinaryenThrow(),
                         BinaryenRethrow(), BinaryenDelegate(), BinaryenCatchAll(),
                         BinaryenReturnCall(), BinaryenReturnCallIndirect(), BinaryenCallRef() 
            };

            directCalls = {
                BinaryenCall(), BinaryenCallIndirect(),
                BinaryenReturnCall(), BinaryenReturnCallIndirect(),
                BinaryenCallRef()
            };

            bulkMemoryOps = {
                BinaryenMemoryInit(), BinaryenDataDrop(),
                BinaryenMemoryCopy(), BinaryenMemoryFill(),
                BinaryenTableInit(),  BinaryenElemDrop(),
                BinaryenTableCopy()
            };

            saturatingTrunc = {
                BinaryenI32TruncSatF32S(), BinaryenI32TruncSatF32U(),
                BinaryenI32TruncSatF64S(), BinaryenI32TruncSatF64U(),
                BinaryenI64TruncSatF32S(), BinaryenI64TruncSatF32U(),
                BinaryenI64TruncSatF64S(), BinaryenI64TruncSatF64U()
            };

            simdConvert = {
                BinaryenF32X4DemoteF64X2Zero(),  BinaryenF64X2PromoteLowF32X4(),
                BinaryenF32X4ConvertI32X4S(),    BinaryenF32X4ConvertI32X4U(),
                BinaryenF64X2ConvertLowI32X4S(), BinaryenF64X2ConvertLowI32X4U()
              };

            moveConst = {
                BinaryenMoveI32(),  BinaryenMoveF32(),
                BinaryenMoveI64(),  BinaryenMoveF64(),
                BinaryenMoveV128(), BinaryenConst32(),
                BinaryenConst64(), BinaryenV128Const()
            };
            
            
            /*──────────── locals & globals ────────────*/
            localGlobal = { BinaryenLocalGet(), BinaryenLocalSet(), BinaryenLocalTee(),
                            BinaryenGlobalGet(), BinaryenGlobalSet()
            };

            /*──────────── memory operations ────────────*/
            memoryOps = {
                // aligned loads
                BinaryenI32Load(), BinaryenI64Load(), BinaryenF32Load(), BinaryenF64Load(),
                // sub-byte / half-word loads
                BinaryenI32Load8S(), BinaryenI32Load8U(), BinaryenI32Load16S(), BinaryenI32Load16U(),
                BinaryenI64Load8S(), BinaryenI64Load8U(), BinaryenI64Load16S(), BinaryenI64Load16U(),
                BinaryenI64Load32S(), BinaryenI64Load32U(),
                // aligned stores
                BinaryenI32Store(), BinaryenI64Store(), BinaryenF32Store(), BinaryenF64Store(),
                // sub-byte / half-word stores
                BinaryenI32Store8(), BinaryenI32Store16(), BinaryenI64Store8(), BinaryenI64Store16(), BinaryenI64Store32(),
                // memory management
                BinaryenMemorySize(), BinaryenMemoryGrow()
            };

            /*──────────── constants ────────────*/
            constOps = { BinaryenI32Const(), BinaryenI64Const(), BinaryenF32Const(), BinaryenF64Const()
            };

            /*──────────── conversions ────────────*/
            conversion = { BinaryenI32WrapI64(), BinaryenI32TruncF32S(), BinaryenI32TruncF32U(),
                           BinaryenI32TruncF64S(), BinaryenI32TruncF64U(), BinaryenI64ExtendI32S(),    
                           BinaryenI64ExtendI32U(), BinaryenI64TruncF32S(), BinaryenI64TruncF32U(),
                           BinaryenI64TruncF64S(), BinaryenI64TruncF64U(), BinaryenF32ConvertI32S(),
                           BinaryenF32ConvertI32U(), BinaryenF32ConvertI64S(), BinaryenF32ConvertI64U(),
                           BinaryenF32DemoteF64(), BinaryenF64ConvertI32S(), BinaryenF64ConvertI32U(),
                           BinaryenF64ConvertI64S(), BinaryenF64ConvertI64U(), BinaryenF64PromoteF32(),
                           BinaryenI32ReinterpretF32(), BinaryenI64ReinterpretF64(),
                           BinaryenF32ReinterpretI32(), BinaryenF64ReinterpretI64()
            };  

            /*──────────── table operations ────────────*/
            tableOps = { BinaryenTableGet(), BinaryenTableSet(), BinaryenTableGrow(),
                        BinaryenTableSize(), BinaryenTableFill(), BinaryenTableCopy()
            };

            /*──────────── reference ops ────────────*/
            refOps = { BinaryenRefNull(), BinaryenRefIsNull(), BinaryenRefFunc()
            };

            /*──────────── atomic operations ────────────*/
            atomicOps = {
                // atomic loads
                BinaryenI32AtomicLoad(), BinaryenI64AtomicLoad(),
                BinaryenI32AtomicLoad8U(), BinaryenI32AtomicLoad16U(),
                BinaryenI64AtomicLoad8U(), BinaryenI64AtomicLoad16U(), BinaryenI64AtomicLoad32U(),
                // atomic stores
                BinaryenI32AtomicStore(), BinaryenI64AtomicStore(),
                BinaryenI32AtomicStore8(), BinaryenI32AtomicStore16(), BinaryenI64AtomicStore8(), BinaryenI64AtomicStore16(), BinaryenI64AtomicStore32(),
                // fences & wait/notify
                BinaryenAtomicFence(), BinaryenMemoryAtomicNotify(),
                BinaryenMemoryAtomicWait32(), BinaryenMemoryAtomicWait64(),
                // read-modify-write ops: add / sub
                BinaryenI32AtomicRmwAdd(), BinaryenI64AtomicRmwAdd(),
                BinaryenI32AtomicRmwSub(), BinaryenI64AtomicRmwSub(),
                // byte/half-word RMW variants
                BinaryenI32AtomicRmw8AddU(), BinaryenI32AtomicRmw16AddU(),
                BinaryenI64AtomicRmw8AddU(), BinaryenI64AtomicRmw16AddU(), BinaryenI64AtomicRmw32AddU(),
                BinaryenI32AtomicRmw8SubU(), BinaryenI32AtomicRmw16SubU(), BinaryenI64AtomicRmw8SubU(), BinaryenI64AtomicRmw16SubU(), BinaryenI64AtomicRmw32SubU(),
                // bitwise RMW: and/or/xor
                BinaryenI32AtomicRmwAnd(), BinaryenI64AtomicRmwAnd(),
                BinaryenI32AtomicRmwOr(), BinaryenI64AtomicRmwOr(),
                BinaryenI32AtomicRmwXor(), BinaryenI64AtomicRmwXor(),
                // byte/half-word bitwise RMW variants
                BinaryenI32AtomicRmw8AndU(), BinaryenI32AtomicRmw16AndU(), BinaryenI64AtomicRmw8AndU(), BinaryenI64AtomicRmw16AndU(), BinaryenI64AtomicRmw32AndU(),
                BinaryenI32AtomicRmw8OrU(), BinaryenI32AtomicRmw16OrU(), BinaryenI64AtomicRmw8OrU(), BinaryenI64AtomicRmw16OrU(), BinaryenI64AtomicRmw32OrU(),
                BinaryenI32AtomicRmw8XorU(), BinaryenI32AtomicRmw16XorU(), BinaryenI64AtomicRmw8XorU(), BinaryenI64AtomicRmw16XorU(), BinaryenI64AtomicRmw32XorU(),
                // exchange & compare-exchange
                BinaryenI32AtomicRmwXchg(), BinaryenI64AtomicRmwXchg(),
                BinaryenI32AtomicRmw8XchgU(), BinaryenI32AtomicRmw16XchgU(), BinaryenI64AtomicRmw8XchgU(), BinaryenI64AtomicRmw16XchgU(), BinaryenI64AtomicRmw32XchgU(),
                BinaryenI32AtomicRmwCmpxchg(), BinaryenI64AtomicRmwCmpxchg(),
                BinaryenI32AtomicRmw8CmpxchgU(), BinaryenI32AtomicRmw16CmpxchgU(), BinaryenI64AtomicRmw8CmpxchgU(), BinaryenI64AtomicRmw16CmpxchgU(), BinaryenI64AtomicRmw32CmpxchgU()
            };    

            init = true;
    }

    using Vec = std::vector<Op>;

    auto pick = [&](const Vec& tbl)->Op{
        if (tbl.size()<2) return opcode;
        std::uniform_int_distribution<size_t> d(0,tbl.size()-1);
        Op alt;
        do { alt = tbl[d(rng)]; } while (alt==opcode);
        return alt;
    };

#define TRY(cat)  if (std::find(cat.begin(),cat.end(),opcode)!=cat.end()) \
                     return pick(cat)

    /* scalar */
    TRY(i32Arith); TRY(i32Bits); TRY(i32Cmp); TRY(i32Unary);
    TRY(i64Arith); TRY(i64Bits); TRY(i64Cmp); TRY(i64Unary);
    TRY(f32Arith); TRY(f32Cmp);  TRY(f32Unary);
    TRY(f64Arith); TRY(f64Cmp);  TRY(f64Unary);

    /* 128-bit SIMD */
    TRY(v128Logic);

    TRY(i8Arith);  TRY(i8Shift);  TRY(i8Cmp);  TRY(i8Unary);
    TRY(i16Arith); TRY(i16Shift); TRY(i16Cmp); TRY(i16Unary);
    TRY(i32xArith);TRY(i32xShift);TRY(i32xCmp);TRY(i32xUnary);
    TRY(i64xArith);TRY(i64xShift);TRY(i64xCmp);TRY(i64xUnary);
    TRY(f32xArith);TRY(f32xCmp);  TRY(f32xUnary);
    TRY(f64xArith);TRY(f64xCmp);  TRY(f64xUnary);
    
    TRY(ctrlFlow);
    TRY(localGlobal);
    TRY(memoryOps);
    TRY(constOps);
    TRY(conversion);
    TRY(tableOps);
    TRY(refOps);
    TRY(atomicOps);
    TRY(directCalls);
    TRY(bulkMemoryOps);
    TRY(saturatingTrunc);
    TRY(simdConvert);
    TRY(moveConst);
    TRY(simdNarrow);
    TRY(simdLaneAccess);
    TRY(simdLaneLoadStore);
    TRY(simdSplatShuffle);
    TRY(simdMemoryOps);
#undef TRY
    return opcode;        // fallback (unchanged)
}


inline bool hasBody(const wasm::Function* f) { return f && f->body; }

using Index = uint32_t;                             // missing typedef on old Binaryen

static inline void mutateSingleConst(BW::Const* c, std::mt19937& rng)
{
    if (!c) return;

    int mode = rng() & 1;               /* 0 = flip, 1 = edge value */

    if (c->type == BW::Type::i32) {
        int32_t v = c->value.geti32();
        int32_t nv = mode ? 0 : (v ^ (1u << (rng() % 32)));
        c->value = BW::Literal(nv);
    }
    else if (c->type == BW::Type::i64) {
        int64_t v = c->value.geti64();
        int64_t nv = mode ? 0 : (v ^ (int64_t(1) << (rng() % 64)));
        c->value = BW::Literal(nv);     /* unambiguous ctor: int64_t           */
    }
    else if (c->type == BW::Type::f32) {
        float  v  = c->value.getf32();
        float  nv = mode ? std::numeric_limits<float>::infinity() : -v;
        c->value  = BW::Literal(nv);
    }
    else if (c->type == BW::Type::f64) {
        double v  = c->value.getf64();
        double nv = mode ? std::numeric_limits<double>::quiet_NaN() : -v;
        c->value  = BW::Literal(nv);
    }
}

// Return the (first) memory name or the default “memory”.
static wasm::Name firstMemoryName(const wasm::Module& m) {
    return m.memories.empty() ? wasm::Name("memory") : m.memories[0]->name;
}

// mutateInstructions  –  module-wide flat walker
void mutateInstructions(BW::Module* module, std::mt19937& rng)
{
    if (!module || module->functions.empty())
        return;

    /* — Commutative opcode set — */
    static const std::unordered_set<Op> kCommutative = {
        /* i32 */ BinaryenI32Add(), BinaryenI32Mul(), BinaryenI32And(),
                 BinaryenI32Or(),  BinaryenI32Xor(),
        /* i64 */ BinaryenI64Add(), BinaryenI64Mul(), BinaryenI64And(),
                 BinaryenI64Or(),  BinaryenI64Xor(),
        /* f32/f64 */ BinaryenF32Add(), BinaryenF32Mul(), BinaryenF32Min(),
                     BinaryenF32Max(), BinaryenF64Add(), BinaryenF64Mul(),
                     BinaryenF64Min(), BinaryenF64Max(),
        /* v128 bit operation */ BinaryenV128And(), BinaryenV128Or(),  BinaryenV128Xor(),
        /* i8x16 */ BinaryenI8x16Add(),      BinaryenI8x16AddSatS(),  BinaryenI8x16AddSatU(),
                    BinaryenI8x16MinS(),     BinaryenI8x16MinU(),
                    BinaryenI8x16MaxS(),     BinaryenI8x16MaxU(),
        /* i16x8 */ BinaryenI16x8Add(),      BinaryenI16x8AddSatS(),  BinaryenI16x8AddSatU(),
                    BinaryenI16x8Mul(),
                    BinaryenI16x8MinS(),     BinaryenI16x8MinU(),
                    BinaryenI16x8MaxS(),     BinaryenI16x8MaxU(),
        /* i32x4 */ BinaryenI32x4Add(),      BinaryenI32x4Mul(),
                    BinaryenI32x4MinS(),     BinaryenI32x4MinU(),
                    BinaryenI32x4MaxS(),     BinaryenI32x4MaxU(),
        /* i64x2 */ BinaryenI64x2Add(),      BinaryenI64x2Mul(),                            
        /* f32x4 & f64x2 */ BinaryenF32x4Add(),      BinaryenF32x4Mul(),
                    BinaryenF32x4Min(),      BinaryenF32x4Max(),
                    BinaryenF64x2Add(),      BinaryenF64x2Mul(),
                    BinaryenF64x2Min(),      BinaryenF64x2Max()
    };

    BW::Builder builder(*module);

    for (auto& fPtr : module->functions) {
        BW::Function* func = fPtr.get();
        if(!func->body) continue;
#ifdef PRINT_LOG
        std::cout << "[mutate] ► " << func->name.str << '\n';
#endif
        std::vector<BW::Expression*> exprs = collectExpressions(func->body);

        for (BW::Expression* e : exprs)
        {
            /* --- Binary -------------------------------------------------- */
            if (auto* bin = e->dynCast<BW::Binary>()) {
                Op oldOp = bin->op;
                Op newOp = getReplacementForOp(oldOp, rng);

                auto isSameLane = [&](Op op) {
                    return BW::Type::getSingleLaneType(
                                BW::getBinaryLaneType(static_cast<BW::BinaryOp>(op)))
                            == bin->left->type;
                };
                    
                bool typeOK = isSameLane(newOp);

                if (typeOK && newOp != oldOp) {
                    bin->op = static_cast<BW::BinaryOp>(newOp);
#ifdef PRINT_LOG
                    std::cout << "  • Binary " << oldOp << " → " << newOp << '\n';
#endif
                }

                if (kCommutative.count(bin->op) && (rng() & 1)) {
                    std::swap(bin->left, bin->right);
#ifdef PRINT_LOG
                    std::cout << "    ↳ operands swapped\n";
#endif
                }
            }

            /* --- Unary --------------------------------------------------- */
            else if (auto* un = e->dynCast<BW::Unary>()) {
                Op cand = getReplacementForOp(un->op, rng);
                if (cand != un->op) {
                    un->op = static_cast<BW::UnaryOp>(cand);
#ifdef PRINT_LOG
                    std::cout << "  • Unary  " << un->op << " → " << cand << '\n';
#endif
                }
            }

            /* --- Const --------------------------------------------------- */
            else if (auto* c = e->dynCast<BW::Const>()) {
                mutateSingleConst(c, rng);
            }

            /* --- Load ---------------------------------------------------- */
            else if (auto* ld = e->dynCast<BW::Load>()) {
                unsigned before = ld->bytes;
                std::vector<unsigned> cand;
                switch (ld->type.getBasic()) {
                    case BW::Type::i32: cand = {1,2,4};      break;
                    case BW::Type::i64: cand = {1,2,4,8};    break;
                    case BW::Type::f32: cand = {4};          break;
                    case BW::Type::f64: cand = {8};          break;
                    default:             cand = {before};    break;
                }
                ld->bytes = ld->align = cand[rng() % cand.size()];
#ifdef PRINT_LOG
                std::cout << "  • Load   width " << before << " → " << ld->bytes << '\n';
#endif
            }

            /* --- Store --------------------------------------------------- */
            else if (auto* st = e->dynCast<BW::Store>()) {
                unsigned before = st->bytes;
                std::vector<unsigned> cand;
                switch (st->valueType.getBasic()) {
                    case BW::Type::i32: cand = {1,2,4};      break;
                    case BW::Type::i64: cand = {1,2,4,8};    break;
                    case BW::Type::f32: cand = {4};          break;
                    case BW::Type::f64: cand = {8};          break;
                    default:             cand = {before};    break;
                }
                st->bytes = st->align = cand[rng() % cand.size()];
#ifdef PRINT_LOG
                std::cout << "  • Store  width " << before << " → " << st->bytes << '\n';
#endif
            }

            /* --- Call ---------------------------------------------------- */
            else if (auto* call = e->dynCast<BW::Call>()) {
                if (module->functions.size() > 1) {
                    size_t idx;
                    do { idx = rng() % module->functions.size(); }
                    while (module->functions[idx]->name == call->target);

                    call->target = module->functions[idx]->name;
#ifdef PRINT_LOG
                    std::cout << "  • Call   retarget → " << call->target.str << '\n';
#endif
                }
            }

            /* --- CallIndirect ------------------------------------------- */
            else if (auto* ci = e->dynCast<BW::CallIndirect>()) {
                if (auto* k = ci->target->dynCast<BW::Const>()) {
                    uint32_t v = k->value.geti32();
                    k->value   = BW::Literal(uint32_t(v ^ 1u));
#ifdef PRINT_LOG
                    std::cout << "  • CallIndirect index toggled\n";
#endif
                }
            }

            /* --- Select -------------------------------------------------- */
            else if (auto* sel = e->dynCast<BW::Select>()) {
                if (rng() & 1) {
                    std::swap(sel->ifTrue, sel->ifFalse);
#ifdef PRINT_LOG
                    std::cout << "  • Select operands swapped\n";
#endif
                } else if (sel->condition->type == BW::Type::i32) {
                    sel->condition = builder.makeUnary(
                        static_cast<BW::UnaryOp>(BinaryenI32Eqz()),
                        sel->condition);
#ifdef PRINT_LOG
                    std::cout << "  • Select condition inverted (eqz)\n";
#endif
                }
            }

            /* --- Drop ---------------------------------------------------- */
            else if (auto* dp = e->dynCast<BW::Drop>()) {
                if (rng() & 1) {
                    dp->value = builder.makeBlock(
                        { builder.makeNop(), dp->value });
#ifdef PRINT_LOG
                    std::cout << "  • Drop wrapped with Nop block\n";
#endif
                }
            }

            /* --- Block duplication -------------------------------------- */
            else if (auto* blk = e->dynCast<BW::Block>()) {
                if (!blk->list.empty() && (rng() & 1)) {
                    size_t i = rng() % blk->list.size();
                    blk->list.push_back(blk->list[i]);   /* shallow copy */
#ifdef PRINT_LOG
                    std::cout << "  • Block duplicated stmt @" << i << '\n';
#endif
                }
            }
        }
    }

    for (auto& fnPtr : module->functions) {
        BW::Function* fn = fnPtr.get();
        if (!fn->body) continue;

        if (rng()%5) continue;

        BW::Block* targetBlock = fn->body->dynCast<BW::Block>();
        if (!targetBlock) {
            targetBlock = builder.makeBlock({fn->body});
            fn->body    = targetBlock;
        }
        int pick = rng() % 6;
        BW::Expression* newInstr = nullptr;

        if (module->memories.empty()) {
            auto mem = std::make_unique<wasm::Memory>();
            mem->name     = "memory";
            mem->initial  = 1;          // one page is enough for fuzzing
            module->addMemory(std::move(mem));
        }

        switch (pick) {
            case 0: { // memory.grow
                auto* pages  = builder.makeConst(wasm::Literal(int32_t(1 + rng()%3)));
                newInstr     = builder.makeMemoryGrow(pages, firstMemoryName(*module));
                break;
            }
            case 1: { // memory.size
                newInstr = builder.makeMemorySize(firstMemoryName(*module));
                break;
            }
            case 2: { // memory.fill
                auto* dest = builder.makeConst(wasm::Literal(int32_t(rng()%64)));
                auto* val  = builder.makeConst(wasm::Literal(int32_t(rng()%256)));
                auto* len  = builder.makeConst(wasm::Literal(int32_t(8)));
                newInstr   = builder.makeMemoryFill(dest, val, len,
                firstMemoryName(*module));
                break;
            }
            case 3: { // ref.null + ref.is_null
                using namespace wasm;
                Type nullExtRef(HeapType::noext, Nullable, Exact);   // null-externref
                auto* refNull = builder.makeRefNull(nullExtRef);
                newInstr      = builder.makeRefIsNull(refNull);
                break;
            }
            case 4: { // typed select (externref)
                using namespace wasm;
                Type nullExtRef(HeapType::noext, Nullable, Exact);  // null-externref
                Type extRef   (HeapType::ext,   Nullable, Inexact); // normal externref
                
                auto* cond = builder.makeConst(Literal(int32_t(0)));
                auto* r1   = builder.makeRefNull(nullExtRef);
                auto* r2   = builder.makeRefNull(nullExtRef);
                auto* sel  = builder.makeSelect(cond, r1, r2);
                sel->type  = extRef;   // result is a *regular* externref
                break;
            }
            case 5: { // formerly “SIMD demo” – disabled on current Binaryen
                newInstr = builder.makeNop();
                break;
            }
        }

        if (!newInstr) continue;

        // Insert at the top of the block
        targetBlock->list.push_back(newInstr);
        std::rotate(targetBlock->list.begin(),
                    targetBlock->list.end() - 1,
                    targetBlock->list.end());   // move to front        
    }

    if (!module->features.has(wasm::FeatureSet::SIMD)) {
        module->features.set(wasm::FeatureSet::SIMD);
    }

    /* --------- Step 3: Verification of module type after mutation --------- */
        BW::WasmValidator v;
        if (!v.validate(*module)) {
            for (auto& fnPtr : module->functions) {
                if (!fnPtr->body)
                    continue;

                if (auto* blk = fnPtr->body->dynCast<BW::Block>()) {
                        if (!blk->list.empty() &&
                             !blk->list[0]->dynCast<BW::Nop>()) {
                             blk->list[0] = builder.makeNop();
                        }
                }
            }
        }
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

        if (!hasBody(func))     
            continue;

        
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

static BW::Function* pickRandomFunctionWithBody(BW::Module* module, std::mt19937& rng)
{
    if (!module || module->functions.empty()) return nullptr;

    /* Randomize up to 8 attempts, then search linearly with fallback */
    for (int tries = 0; tries < 8; ++tries) {
        BW::Function* cand = module->functions[rng() % module->functions.size()].get();
        if (cand && cand->body) return cand;
    }
    
    for (auto& f : module->functions)
        if (f->body) return f.get();
    
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

    BW::Function* func = pickRandomFunctionWithBody(module, rng);
    if (!func) return;   

    
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

static BW::Block* ensureBlock(BW::Builder& B, BW::Expression*& body) {
    if (auto* blk = body->dynCast<BW::Block>()) return blk;
    body = B.makeBlock({ body });
    return body->dynCast<BW::Block>();   // now definitely a block
}

static inline void prepend(ArenaVector<BW::Expression*>& vec, BW::Expression* expr)
{
    vec.push_back(expr);                      // 1. append
    std::rotate(vec.begin(), vec.end() - 1, vec.end()); // 2. rotate last → front
}

//-----------------------------------------------------------------------------
// Control-Flow Mutation: Modify branch conditions in control expressions.
void mutateControlFlow(BW::Module* module, std::mt19937& rng)
{
    if (!module || module->functions.empty()) return;

    BW::Builder builder(*module);

    for (auto& fptr : module->functions) {
        BW::Function* func = fptr.get();
        if (!hasBody(func)) continue;

        std::vector<BW::Expression*> exprs = collectExpressions(func->body);
        bool mutated = false;

        for (auto* expr : exprs) {

            /* ───────────────── Break / br_if ───────────────── */
            if (auto* br = expr->dynCast<BW::Break>()) {
                if (br->condition) {
                    switch (rng() % 3) {
                    case 0:  // toggle
                        br->condition = builder.makeUnary(
                            static_cast<BW::UnaryOp>(BinaryenI32Eqz()),
                            br->condition);
                        break;
                    case 1:  // remove
                        br->condition = builder.makeNop();
                        break;
                    case 2:  // constant
                        br->condition = builder.makeConst(
                            BW::Literal(int32_t(rng() & 1)));
                        break;
                    }
                }

                if (!(br->name == BW::Name()) && (rng() & 1)) {
                    std::string old = std::string(br->name.str);
                    br->name        = BW::Name(old + "_mut");
                }
                mutated = true;
            }

            /* ───────────────── Loop ───────────────── */
            else if (auto* loop = expr->dynCast<BW::Loop>()) {
                int style = rng() % 3;
                BW::Block* body = ensureBlock(builder, loop->body);

                switch (style) {
                case 0: {  // early break
                    auto* brk = builder.makeBreak(
                        BW::Name(), nullptr,
                        builder.makeConst(BW::Literal(int32_t(1))));
                    prepend(body->list, brk);
                    break;
                }
                case 1: {  // if(cond) break;
                    auto* cond  = builder.makeConst(
                        BW::Literal(int32_t(rng() & 1)));
                    auto* ifBrk = builder.makeIf(
                        cond, builder.makeBreak(loop->name));
                    prepend(body->list, ifBrk);
                    break;
                }
                case 2: {  // wrap with outer loop
                    auto* outer = builder.makeLoop(
                        BW::Name(std::string(loop->name.str) + "_wrap"),
                        loop);
                    prepend(body->list, outer);
                    break;
                }
                }
                mutated = true;
            }

            /* ───────────────── If / Else ───────────────── */
            else if (auto* iff = expr->dynCast<BW::If>()) {
                if (iff->ifFalse && (rng() & 1)) {           // swap then/else
                    std::swap(iff->ifTrue, iff->ifFalse);
                    iff->condition = builder.makeUnary(
                        static_cast<BW::UnaryOp>(BinaryenI32Eqz()),
                        iff->condition);
                    mutated = true;
                } else if (!iff->ifFalse && (rng() % 10 < 3)) {
                    iff->ifFalse = builder.makeNop();
                    mutated = true;
                }
            }

            /* ───────────────── Select ───────────────── */
            else if (auto* sel = expr->dynCast<BW::Select>()) {
                if (rng() & 1) {
                    std::swap(sel->ifTrue, sel->ifFalse);
                    sel->condition = builder.makeUnary(
                        static_cast<BW::UnaryOp>(BinaryenI32Eqz()),
                        sel->condition);
                    mutated = true;
                }
            }
        } // for-expr

#ifdef PRINT_LOG
        if (!mutated)
            std::cout << "[mutateCF] nothing changed in "
                      << func->name.str << '\n';
#endif
    } // for-function
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
        
        if (!hasBody(func))     
            continue;

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

            BW::Block* blk = ensureBlock(builder, func->body);
            prepend(blk->list, recCall);   
        
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

        mutateInstructions(module, rng);

        int strat = rng() % 5;
        // fprintf(stderr, "custom mutator cov test strat: %d", strat);
        switch (strat) {
        case 0:
            mutateConstantExpressions(module, rng);
            break;
        case 1:
            mutateSection(module, dummyStore, rng);
            break;
        case 2:
            mutateSemantic(module, rng);
            break;
        case 3:
            mutateControlFlow(module, rng);
            break;
        case 4:
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
