/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstdlib>

#include "test_mock_webview_controller.h"
#include "web_errors.h"

// 引入被测实现：napi_webview_controller.cpp（经 WEBVIEW_UNIT_TEST 编译期 seam 使用 mock WebviewController）。
// private 宏仅在解析生产头文件期间放开（对齐 napi_web_cookie_manager_test 既有做法），使
// NapiWebviewController 的 private 静态方法（enableAutoReload/isAutoReloadEnabled）可被单测直调；
// STL 与 SDK 头已在宏外先行解析（include guard 短路重复引入），生产文件保持零改动。
#define private public
#include "napi_webview_controller.cpp"
#undef private

using namespace testing;
using namespace OHOS;
using namespace OHOS::NWeb;

namespace {
// ===== napi 函数桩状态（可注入场景） =====
constexpr size_t MAX_MOCK_ARGC = 4;
size_t g_mockArgc = 0;
napi_value g_mockArgv[MAX_MOCK_ARGC] = {nullptr, nullptr, nullptr, nullptr};
napi_value g_mockThisArg = nullptr;
void* g_unwrapResult = nullptr;
napi_status g_unwrapStatus = napi_ok;
napi_valuetype g_typeofResult = napi_boolean;
bool g_mockBoolValue = false;
bool g_getBooleanCalled = false;
bool g_getBooleanValue = false;
bool g_throwCalled = false;
int32_t g_lastThrownCode = 0;

// napi_value 哨兵（生产代码仅与 nullptr 比较，不解引用）
constexpr uintptr_t MOCK_ENV_ADDR = 0x1;
constexpr uintptr_t MOCK_CBINFO_ADDR = 0x2;
constexpr uintptr_t MOCK_ARG_ADDR = 0x10;
constexpr uintptr_t MOCK_RESULT_ADDR = 0x20;

void ResetNapiMockState()
{
    g_mockArgc = 0;
    for (size_t i = 0; i < MAX_MOCK_ARGC; ++i) {
        g_mockArgv[i] = nullptr;
    }
    g_mockThisArg = reinterpret_cast<napi_value>(MOCK_ARG_ADDR);
    g_unwrapResult = nullptr;
    g_unwrapStatus = napi_ok;
    g_typeofResult = napi_boolean;
    g_mockBoolValue = false;
    g_getBooleanCalled = false;
    g_getBooleanValue = false;
    g_throwCalled = false;
    g_lastThrownCode = 0;
}
} // namespace

// ===== napi 函数桩（链接期绑定：本可执行文件内定义优先于 libace_napi.so） =====
// 仅覆盖被测路径（enableAutoReload/isAutoReloadEnabled 链路）实际调用的 napi 接口；
// 签名与 SDK node_api.h 声明保持一致（声明先行，定义继承其链接属性）。

// 签名由 SDK node_api.h 声明固定（Node-API ABI）：桩须与头文件声明逐参一致方可通过编译校验并完成
// 链接期符号替换，参数个数不可缩减或聚合，G.FUN.01 参数个数建议在此不适用。
// NOLINT
napi_status napi_get_cb_info(napi_env env, napi_callback_info cbinfo, size_t* argc, napi_value* argv,
    napi_value* thisArg, void** data)
{
    if (thisArg != nullptr) {
        *thisArg = g_mockThisArg;
    }
    if (argc != nullptr && argv != nullptr) {
        size_t capacity = *argc;
        size_t count = (g_mockArgc < capacity) ? g_mockArgc : capacity;
        for (size_t i = 0; i < count; ++i) {
            argv[i] = g_mockArgv[i];
        }
        *argc = g_mockArgc;
    }
    return napi_ok;
}

napi_status napi_get_undefined(napi_env env, napi_value* result)
{
    if (result != nullptr) {
        *result = reinterpret_cast<napi_value>(MOCK_RESULT_ADDR);
    }
    return napi_ok;
}

napi_status napi_get_boolean(napi_env env, bool value, napi_value* result)
{
    g_getBooleanCalled = true;
    g_getBooleanValue = value;
    if (result != nullptr) {
        *result = reinterpret_cast<napi_value>(MOCK_RESULT_ADDR);
    }
    return napi_ok;
}

napi_status napi_unwrap(napi_env env, napi_value jsObject, void** result)
{
    if (result != nullptr) {
        *result = g_unwrapResult;
    }
    return g_unwrapStatus;
}

napi_status napi_typeof(napi_env env, napi_value value, napi_valuetype* result)
{
    if (result != nullptr) {
        *result = g_typeofResult;
    }
    return napi_ok;
}

napi_status napi_get_value_bool(napi_env env, napi_value value, bool* result)
{
    if (result != nullptr) {
        *result = g_mockBoolValue;
    }
    return napi_ok;
}

napi_status napi_throw_error(napi_env env, const char* code, const char* msg)
{
    g_throwCalled = true;
    if (code != nullptr) {
        g_lastThrownCode = static_cast<int32_t>(std::atoi(code));
    }
    return napi_ok;
}

// 保险桩：覆盖 NAPI_CALL 宏失败路径可能触达的 last_error 查询（成功路径不调用）
napi_status napi_get_last_error_info(napi_env env, const napi_extended_error_info** result)
{
    static napi_extended_error_info emptyInfo = { nullptr, 0, napi_ok };
    if (result != nullptr) {
        *result = &emptyInfo;
    }
    return napi_ok;
}

namespace OHOS {
namespace NWeb {
class NapiWebviewControllerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

protected:
    bool WasErrorThrown() const
    {
        return g_throwCalled;
    }

    int32_t GetLastErrorCode() const
    {
        return g_lastThrownCode;
    }

    void ResetErrorState()
    {
        g_throwCalled = false;
        g_lastThrownCode = 0;
    }

    napi_env GetMockEnv() const
    {
        return reinterpret_cast<napi_env>(MOCK_ENV_ADDR);
    }

    napi_callback_info GetMockInfo() const
    {
        return reinterpret_cast<napi_callback_info>(MOCK_CBINFO_ADDR);
    }

    // 构造一次合法调用：argc=1、入参为 boolean、unwrap 到 controller
    void PrepareValidCall(WebviewController& controller)
    {
        g_unwrapResult = &controller;
        g_mockArgc = 1;
        g_mockArgv[0] = reinterpret_cast<napi_value>(MOCK_ARG_ADDR);
        g_typeofResult = napi_boolean;
    }
};

void NapiWebviewControllerTest::SetUpTestCase(void) {}

void NapiWebviewControllerTest::TearDownTestCase(void) {}

void NapiWebviewControllerTest::SetUp(void)
{
    ResetNapiMockState();
    WebviewController::ResetMock();
}

void NapiWebviewControllerTest::TearDown(void) {}

/**
 * @tc.name: SetAutoReloadEnabled_Success
 * @tc.desc: SetAutoReloadEnabled.
 * @tc.type: FUNC
 * @tc.require: 20260812039196
 */
TEST_F(NapiWebviewControllerTest, SetAutoReloadEnabled_Success)
{
    WebviewController controller;
    controller.SetInitialized(true);
    PrepareValidCall(controller);
    napi_env env = GetMockEnv();
    napi_callback_info info = GetMockInfo();

    // Set(true)
    g_mockBoolValue = true;
    EXPECT_NE(NapiWebviewController::SetAutoReloadEnabled(env, info), nullptr);
    EXPECT_FALSE(WasErrorThrown());
    g_getBooleanCalled = false;
    EXPECT_NE(NapiWebviewController::IsAutoReloadEnabled(env, info), nullptr);
    EXPECT_TRUE(g_getBooleanCalled);
    EXPECT_TRUE(g_getBooleanValue);

    // Set(false)
    g_mockBoolValue = false;
    EXPECT_NE(NapiWebviewController::SetAutoReloadEnabled(env, info), nullptr);
    EXPECT_FALSE(WasErrorThrown());
    g_getBooleanCalled = false;
    EXPECT_NE(NapiWebviewController::IsAutoReloadEnabled(env, info), nullptr);
    EXPECT_TRUE(g_getBooleanCalled);
    EXPECT_FALSE(g_getBooleanValue);
}

/**
 * @tc.name: SetAutoReloadEnabled_ErrorScenarios
 * @tc.desc: SetAutoReloadEnabled.
 * @tc.type: FUNC
 * @tc.require: 20260812039196
 */
TEST_F(NapiWebviewControllerTest, SetAutoReloadEnabled_ErrorScenarios)
{
    WebviewController controller;
    controller.SetInitialized(true);
    PrepareValidCall(controller);
    napi_env env = GetMockEnv();
    napi_callback_info info = GetMockInfo();
    g_mockBoolValue = true;

    // Argument count is not one
    g_mockArgc = 0;
    EXPECT_NE(NapiWebviewController::SetAutoReloadEnabled(env, info), nullptr);
    EXPECT_TRUE(WasErrorThrown());
    EXPECT_EQ(GetLastErrorCode(), PARAM_CHECK_ERROR);
    ResetErrorState();
    g_mockArgc = 1;

    // Argument type is not boolean
    g_typeofResult = napi_number;
    EXPECT_EQ(NapiWebviewController::SetAutoReloadEnabled(env, info), nullptr);
    EXPECT_TRUE(WasErrorThrown());
    EXPECT_EQ(GetLastErrorCode(), PARAM_CHECK_ERROR);
    ResetErrorState();
    g_typeofResult = napi_boolean;

    // Controller is null
    g_unwrapResult = nullptr;
    EXPECT_EQ(NapiWebviewController::SetAutoReloadEnabled(env, info), nullptr);
    EXPECT_TRUE(WasErrorThrown());
    EXPECT_EQ(GetLastErrorCode(), INIT_ERROR);
    ResetErrorState();
    g_unwrapResult = &controller;

    // Controller is not initialized
    controller.SetInitialized(false);
    EXPECT_EQ(NapiWebviewController::SetAutoReloadEnabled(env, info), nullptr);
    EXPECT_TRUE(WasErrorThrown());
    EXPECT_EQ(GetLastErrorCode(), INIT_ERROR);
    ResetErrorState();
    controller.SetInitialized(true);

    // SetAutoReloadEnabled returns error
    WebviewController::SetAutoReloadShouldFail(true);
    EXPECT_EQ(NapiWebviewController::SetAutoReloadEnabled(env, info), nullptr);
    EXPECT_TRUE(WasErrorThrown());
    EXPECT_EQ(GetLastErrorCode(), PARAM_CHECK_ERROR);
    WebviewController::SetAutoReloadShouldFail(false);
}

/**
 * @tc.name: IsAutoReloadEnabled_Success
 * @tc.desc: IsAutoReloadEnabled.
 * @tc.type: FUNC
 * @tc.require: 20260812039196
 */
TEST_F(NapiWebviewControllerTest, IsAutoReloadEnabled_Success)
{
    WebviewController controller;
    controller.SetInitialized(true);
    PrepareValidCall(controller);
    napi_env env = GetMockEnv();
    napi_callback_info info = GetMockInfo();

    // Default value is false
    g_getBooleanCalled = false;
    EXPECT_NE(NapiWebviewController::IsAutoReloadEnabled(env, info), nullptr);
    EXPECT_TRUE(g_getBooleanCalled);
    EXPECT_FALSE(g_getBooleanValue);
    EXPECT_FALSE(WasErrorThrown());

    // Returns the last set value
    g_mockBoolValue = true;
    EXPECT_NE(NapiWebviewController::SetAutoReloadEnabled(env, info), nullptr);
    g_getBooleanCalled = false;
    EXPECT_NE(NapiWebviewController::IsAutoReloadEnabled(env, info), nullptr);
    EXPECT_TRUE(g_getBooleanCalled);
    EXPECT_TRUE(g_getBooleanValue);
}

/**
 * @tc.name: IsAutoReloadEnabled_ErrorScenarios
 * @tc.desc: IsAutoReloadEnabled.
 * @tc.type: FUNC
 * @tc.require: 20260812039196
 */
TEST_F(NapiWebviewControllerTest, IsAutoReloadEnabled_ErrorScenarios)
{
    WebviewController controller;
    controller.SetInitialized(true);
    PrepareValidCall(controller);
    napi_env env = GetMockEnv();
    napi_callback_info info = GetMockInfo();

    // Controller is null
    g_unwrapResult = nullptr;
    EXPECT_EQ(NapiWebviewController::IsAutoReloadEnabled(env, info), nullptr);
    EXPECT_TRUE(WasErrorThrown());
    EXPECT_EQ(GetLastErrorCode(), INIT_ERROR);
    ResetErrorState();
    g_unwrapResult = &controller;

    // Controller is not initialized
    controller.SetInitialized(false);
    EXPECT_EQ(NapiWebviewController::IsAutoReloadEnabled(env, info), nullptr);
    EXPECT_TRUE(WasErrorThrown());
    EXPECT_EQ(GetLastErrorCode(), INIT_ERROR);
    ResetErrorState();
    controller.SetInitialized(true);
}
} // namespace NWeb
} // namespace OHOS
