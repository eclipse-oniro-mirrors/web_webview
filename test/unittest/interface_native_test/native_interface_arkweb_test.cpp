/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <securec.h>
#include <thread>

#include "parameter.h"
#include "parameters.h"

#define private public
#include "arkweb_utils.h"
#include "native_interface_arkweb.h"
#include "nweb.h"
#include "nweb_helper.h"

#include "base/web/webview/interfaces/native/native_javascript_execute_callback.h"
#undef private

#include "event_handler.h"
#include "event_runner.h"
#include "mock/nweb_full_mock.h"
#include "native_arkweb_utils.h"

using namespace testing;
using namespace testing::ext;
using ::testing::AnyOf;

namespace {
    constexpr int32_t PROXY_METHOD_COUNT = 2;
    ArkWeb_ErrorCode g_errorCode = ArkWeb_ErrorCode::ARKWEB_SUCCESS;
    void OH_ArkWeb_OnCookieSaveCallbackImpl(ArkWeb_ErrorCode errorCode) {
        g_errorCode = errorCode;
    }

    void OH_ArkWeb_OnCookieFetchCallbackImpl(ArkWeb_ErrorCode errorCode, char* cookieValue) {
        g_errorCode = errorCode;
    }
}

namespace OHOS {
namespace NWeb {

class NativeInterfaceArkWebTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static int paramEnforce;
};

int NativeInterfaceArkWebTest::paramEnforce = 0;

void NativeInterfaceArkWebTest::SetUpTestCase(void)
{
    paramEnforce = OHOS::system::GetIntParameter("web.engine.enforce", 0);
}

void NativeInterfaceArkWebTest::TearDownTestCase(void)
{
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(paramEnforce));
}

void NativeInterfaceArkWebTest::SetUp(void) {}

void NativeInterfaceArkWebTest::TearDown(void) {}

/**
 * @tc.name  : OHNativeInterfaceArkWebTest_OH_NativeArkWeb_OH_NativeArkWeb_RunJavaScript_01
 * @tc.desc  : Test OH_NativeArkWeb_RunJavaScript
 */
HWTEST_F(NativeInterfaceArkWebTest,
         OHNativeInterfaceArkWebTest_OH_NativeArkWeb_OH_NativeArkWeb_RunJavaScript_01, TestSize.Level1) {
    const char* webTag = "";
    const char* jsCode = "";
    NativeArkWeb_OnJavaScriptCallback callback = nullptr;
    OH_NativeArkWeb_RunJavaScript(webTag, jsCode, callback);
}

/**
 * @tc.name  : OHNativeInterfaceArkWebTest_OH_NativeArkWeb_OH_NativeArkWeb_RegisterJavaScriptProxy_01
 * @tc.desc  : Test OH_NativeArkWeb_RegisterJavaScriptProxy
 */
HWTEST_F(NativeInterfaceArkWebTest,
         OHNativeInterfaceArkWebTest_OH_NativeArkWeb_OH_NativeArkWeb_RegisterJavaScriptProxy_01, TestSize.Level1) {
    const char* webTag = "";
    const char* objName = "";
    const char* methodName[3] = { "method1", "method2", "method3" };
    NativeArkWeb_OnJavaScriptProxyCallback callback[3] = { nullptr, nullptr, nullptr };
    int32_t size = 3;
    OH_NativeArkWeb_RegisterJavaScriptProxy(webTag, objName, methodName, callback, size, false);
}

/**
 * @tc.name  : OHNativeInterfaceArkWebTest_OH_NativeArkWeb_UnregisterJavaScriptProxy_01
 * @tc.desc  : Test OH_NativeArkWeb_UnregisterJavaScriptProxy
 */
HWTEST_F(NativeInterfaceArkWebTest,
         OHNativeInterfaceArkWebTest_OH_NativeArkWeb_UnregisterJavaScriptProxy_01, TestSize.Level1) {
    const char* webTag = "";
    const char* objName = "";
    OH_NativeArkWeb_UnregisterJavaScriptProxy(webTag, objName);
}

/**
 * @tc.name  : OHNativeInterfaceArkWebTest_OH_NativeArkWeb_SetDestroyCallback_01
 * @tc.desc  : Test OH_NativeArkWeb_SetDestroyCallback
 */
HWTEST_F(NativeInterfaceArkWebTest,
         OHNativeInterfaceArkWebTest_OH_NativeArkWeb_SetDestroyCallback_01, TestSize.Level1) {
    const char* webTag = "";
    NativeArkWeb_OnDestroyCallback callback = nullptr;
    OH_NativeArkWeb_SetDestroyCallback(webTag, callback);
}

/**
 * @tc.name  : OHNativeInterfaceArkWebTest_OH_NativeArkWeb_GetDestroyCallback_01
 * @tc.desc  : Test OH_NativeArkWeb_GetDestroyCallback
 */
HWTEST_F(NativeInterfaceArkWebTest,
         OHNativeInterfaceArkWebTest_OH_NativeArkWeb_GetDestroyCallback_01, TestSize.Level1) {
    const char* webTag = "";
    NativeArkWeb_OnDestroyCallback callback = OH_NativeArkWeb_GetDestroyCallback(webTag);
    EXPECT_TRUE(callback == nullptr);
}

/**
 * @tc.name  : OHNativeInterfaceArkWebTest_OH_NativeArkWeb_SetJavaScriptProxyValidCallback_01
 * @tc.desc  : Test OH_NativeArkWeb_SetJavaScriptProxyValidCallback
 */
HWTEST_F(NativeInterfaceArkWebTest,
         OHNativeInterfaceArkWebTest_OH_NativeArkWeb_SetJavaScriptProxyValidCallback_01, TestSize.Level1) {
    const char* webTag = "";
    NativeArkWeb_OnValidCallback callback = nullptr;
    OH_NativeArkWeb_SetJavaScriptProxyValidCallback(webTag, callback);
}

/**
 * @tc.name  : OHNativeInterfaceArkWebTest_OH_NativeArkWeb_GetJavaScriptProxyValidCallback_01
 * @tc.desc  : Test OH_NativeArkWeb_GetJavaScriptProxyValidCallback
 */
HWTEST_F(NativeInterfaceArkWebTest,
         OHNativeInterfaceArkWebTest_OH_NativeArkWeb_GetJavaScriptProxyValidCallback_01, TestSize.Level1) {
    const char* webTag = "";
    NativeArkWeb_OnValidCallback callback =
        OH_NativeArkWeb_GetJavaScriptProxyValidCallback(webTag);
    EXPECT_TRUE(callback == nullptr);
}

/**
 * @tc.name  : OH_NativeArkWeb_GetBlanklessInfoWithKey_01
 * @tc.desc  : Test OH_NativeArkWeb_GetBlanklessInfoWithKey
 */
 HWTEST_F(NativeInterfaceArkWebTest, OH_NativeArkWeb_GetBlanklessInfoWithKey_01, TestSize.Level1) {
    bool enabled = OHOS::system::GetBoolParameter("web.blankless.enabled", false);

    OHOS::system::SetParameter("web.blankless.enabled", "true");
    auto info0 = OH_NativeArkWeb_GetBlanklessInfoWithKey("", nullptr);
    EXPECT_EQ(info0.errCode, ArkWeb_BlanklessErrorCode::ARKWEB_BLANKLESS_ERR_INVALID_ARGS);
    auto info1 = OH_NativeArkWeb_GetBlanklessInfoWithKey("", "");
    EXPECT_EQ(info1.errCode, ArkWeb_BlanklessErrorCode::ARKWEB_BLANKLESS_ERR_INVALID_ARGS);
    auto info2 = OH_NativeArkWeb_GetBlanklessInfoWithKey("", "OH_NativeArkWeb_GetBlanklessInfoWithKey");
    EXPECT_EQ(info2.errCode, ArkWeb_BlanklessErrorCode::ARKWEB_BLANKLESS_ERR_UNKNOWN);

    OHOS::system::SetParameter("web.blankless.enabled", "false");
    auto info3 = OH_NativeArkWeb_GetBlanklessInfoWithKey("", "");
    EXPECT_EQ(info3.errCode, ArkWeb_BlanklessErrorCode::ARKWEB_BLANKLESS_ERR_DEVICE_NOT_SUPPORT);
    auto info4 = OH_NativeArkWeb_GetBlanklessInfoWithKey("", "OH_NativeArkWeb_GetBlanklessInfoWithKey");
    EXPECT_EQ(info4.errCode, ArkWeb_BlanklessErrorCode::ARKWEB_BLANKLESS_ERR_DEVICE_NOT_SUPPORT);

    OHOS::system::SetParameter("web.blankless.enabled", enabled ? "true" : "false");
}

/**
 * @tc.name  : OH_NativeArkWeb_SetBlanklessLoadingWithKey_01
 * @tc.desc  : Test OH_NativeArkWeb_SetBlanklessLoadingWithKey
 */
HWTEST_F(NativeInterfaceArkWebTest, OH_NativeArkWeb_SetBlanklessLoadingWithKey_01, TestSize.Level1) {
    bool enabled = OHOS::system::GetBoolParameter("web.blankless.enabled", false);

    OHOS::system::SetParameter("web.blankless.enabled", "true");
    auto errCode0 = OH_NativeArkWeb_SetBlanklessLoadingWithKey("", nullptr, true);
    EXPECT_EQ(errCode0, ArkWeb_BlanklessErrorCode::ARKWEB_BLANKLESS_ERR_INVALID_ARGS);
    auto errCode1 = OH_NativeArkWeb_SetBlanklessLoadingWithKey("", "", true);
    EXPECT_EQ(errCode1, ArkWeb_BlanklessErrorCode::ARKWEB_BLANKLESS_ERR_INVALID_ARGS);
    auto errCode2 = OH_NativeArkWeb_SetBlanklessLoadingWithKey("", "OH_NativeArkWeb_SetBlanklessLoadingWithKey", false);
    EXPECT_EQ(errCode2, ArkWeb_BlanklessErrorCode::ARKWEB_BLANKLESS_ERR_UNKNOWN);

    OHOS::system::SetParameter("web.blankless.enabled", "false");
    auto errCode3 = OH_NativeArkWeb_SetBlanklessLoadingWithKey("", "", true);
    EXPECT_EQ(errCode3, ArkWeb_BlanklessErrorCode::ARKWEB_BLANKLESS_ERR_DEVICE_NOT_SUPPORT);
    auto errCode4 = OH_NativeArkWeb_SetBlanklessLoadingWithKey("", "OH_NativeArkWeb_SetBlanklessLoadingWithKey", false);
    EXPECT_EQ(errCode4, ArkWeb_BlanklessErrorCode::ARKWEB_BLANKLESS_ERR_DEVICE_NOT_SUPPORT);

    OHOS::system::SetParameter("web.blankless.enabled", enabled ? "true" : "false");
}

/**
 * @tc.name  : OH_NativeArkWeb_ClearBlanklessLoadingCache_01
 * @tc.desc  : Test OH_NativeArkWeb_ClearBlanklessLoadingCache
 */
HWTEST_F(NativeInterfaceArkWebTest, OH_NativeArkWeb_ClearBlanklessLoadingCache_01, TestSize.Level1) {
    bool enabled = OHOS::system::GetBoolParameter("web.blankless.enabled", false);

    OHOS::system::SetParameter("web.blankless.enabled", "false");
    OH_NativeArkWeb_ClearBlanklessLoadingCache(nullptr, 0);

    OHOS::system::SetParameter("web.blankless.enabled", "true");
    OH_NativeArkWeb_ClearBlanklessLoadingCache(nullptr, 0);

    const char* keys1[] = {};
    EXPECT_EQ(sizeof(keys1) / sizeof(const char*), 0);
    OH_NativeArkWeb_ClearBlanklessLoadingCache(keys1, 0);

    std::string longStr;
    // Test for key length over MAX_KEY_LENGTH, which is 2048.
    for (uint32_t idx = 0; idx < 3000; idx++) {
        longStr += "0";
    }
    const char* keys2[3];
    keys2[0] = "ClearBlanklessLoadingCache";
    keys2[1] = "";
    keys2[2] = longStr.c_str();
    EXPECT_EQ(sizeof(keys2) / sizeof(const char*), 3);
    OH_NativeArkWeb_ClearBlanklessLoadingCache(keys2, 3);

    const char* keys3[101];
    // Test for keys size over MAX_KEYS_COUNT, which is 100.
    for (uint32_t idx = 0; idx < 101; idx++) {
        keys3[idx] = "test";
    }
    EXPECT_EQ(sizeof(keys3) / sizeof(const char*), 101);
    OH_NativeArkWeb_ClearBlanklessLoadingCache(keys3, 101);

    const char* keys4[] = { nullptr };
    EXPECT_EQ(sizeof(keys4) / sizeof(const char*), 1);
    OH_NativeArkWeb_ClearBlanklessLoadingCache(keys4, 1);

    OHOS::system::SetParameter("web.blankless.enabled", enabled ? "true" : "false");
}

/**
 * @tc.name  : OH_NativeArkWeb_SetBlanklessLoadingCacheCapacity_01
 * @tc.desc  : Test OH_NativeArkWeb_SetBlanklessLoadingCacheCapacity
 */
HWTEST_F(NativeInterfaceArkWebTest, OH_NativeArkWeb_SetBlanklessLoadingCacheCapacity_01, TestSize.Level1) {
    bool enabled = OHOS::system::GetBoolParameter("web.blankless.enabled", false);

    OHOS::system::SetParameter("web.blankless.enabled", "true");
    EXPECT_EQ(OH_NativeArkWeb_SetBlanklessLoadingCacheCapacity(0), 0);
    EXPECT_EQ(OH_NativeArkWeb_SetBlanklessLoadingCacheCapacity(20), 20);
    EXPECT_EQ(OH_NativeArkWeb_SetBlanklessLoadingCacheCapacity(100), 100);
    EXPECT_EQ(OH_NativeArkWeb_SetBlanklessLoadingCacheCapacity(1000), 100);

    OHOS::system::SetParameter("web.blankless.enabled", "false");
    EXPECT_EQ(OH_NativeArkWeb_SetBlanklessLoadingCacheCapacity(0), 0);
    EXPECT_EQ(OH_NativeArkWeb_SetBlanklessLoadingCacheCapacity(20), 0);
    EXPECT_EQ(OH_NativeArkWeb_SetBlanklessLoadingCacheCapacity(100), 0);
    EXPECT_EQ(OH_NativeArkWeb_SetBlanklessLoadingCacheCapacity(1000), 0);

    OHOS::system::SetParameter("web.blankless.enabled", enabled ? "true" : "false");
}

/**
 * @tc.name  : OH_NativeArkWeb_Blankless_Dual_Core_01
 * @tc.desc  : Test OH_NativeArkWeb_Blankless_Dual_Core
 */
HWTEST_F(NativeInterfaceArkWebTest, OH_NativeArkWeb_Blankless_Dual_Core_01, TestSize.Level1) {
    bool defaultStatus = OHOS::system::GetBoolParameter("web.blankless.enabled", false);
    OHOS::system::SetParameter("web.blankless.enabled", "true");
    OHOS::system::SetParameter("web.engine.enforce", "0");
    auto version = ArkWeb::getActiveWebEngineVersion();
    ArkWeb::setActiveWebEngineVersion(ArkWeb::ArkWebEngineVersion::M132);
    auto info = OH_NativeArkWeb_GetBlanklessInfoWithKey("", "");
    EXPECT_EQ(info.errCode, ArkWeb_BlanklessErrorCode::ARKWEB_BLANKLESS_ERR_INVALID_ARGS);
    auto errCode = OH_NativeArkWeb_SetBlanklessLoadingWithKey("", "", true);
    EXPECT_EQ(errCode, ArkWeb_BlanklessErrorCode::ARKWEB_BLANKLESS_ERR_INVALID_ARGS);
    OH_NativeArkWeb_ClearBlanklessLoadingCache(nullptr, 0);
    EXPECT_EQ(OH_NativeArkWeb_SetBlanklessLoadingCacheCapacity(20), 20);

    ArkWeb::setActiveWebEngineVersion(version);
    OHOS::system::SetParameter("web.blankless.enabled", defaultStatus ? "true" : "false");
}

/**
 * @tc.name  : OH_ArkWebCookieManager_SaveCookieSync_01
 * @tc.desc  : Test OH_ArkWebCookieManager_SaveCookieSync
 */
HWTEST_F(NativeInterfaceArkWebTest, OH_ArkWebCookieManager_SaveCookieSync_01, TestSize.Level1) {
    ArkWeb_ErrorCode ret = OH_ArkWebCookieManager_SaveCookieSync();
    EXPECT_EQ(ret, ArkWeb_ErrorCode::ARKWEB_COOKIE_MANAGER_INITIALIZE_FAILED);
}

/**
 * @tc.name  : OH_ArkWebCookieManager_SaveCookieAsync_01
 * @tc.desc  : Test OH_ArkWebCookieManager_SaveCookieAsync
 */
HWTEST_F(NativeInterfaceArkWebTest, OH_ArkWebCookieManager_SaveCookieAsync_01, TestSize.Level1) {
    OH_ArkWeb_OnCookieSaveCallback callback = nullptr;
    g_errorCode = ArkWeb_ErrorCode::ARKWEB_SUCCESS;
    OH_ArkWebCookieManager_SaveCookieAsync(callback);
    EXPECT_EQ(g_errorCode, ArkWeb_ErrorCode::ARKWEB_SUCCESS);

    g_errorCode = ArkWeb_ErrorCode::ARKWEB_SUCCESS;
    callback = OH_ArkWeb_OnCookieSaveCallbackImpl;
    OH_ArkWebCookieManager_SaveCookieAsync(callback);
    EXPECT_EQ(g_errorCode, ArkWeb_ErrorCode::ARKWEB_COOKIE_MANAGER_INITIALIZE_FAILED);
}

/**
 * @tc.name  : OH_ArkWebCookieManager_FetchCookieSync_01
 * @tc.desc  : Test OH_ArkWebCookieManager_FetchCookieSync
 */
HWTEST_F(NativeInterfaceArkWebTest, OH_ArkWebCookieManager_FetchCookieSync_01, TestSize.Level1) {
    char *cookie = nullptr;
    ArkWeb_ErrorCode ret = OH_ArkWebCookieManager_FetchCookieSync("", false, false, false, &cookie);
    EXPECT_EQ(ret, ArkWeb_ErrorCode::ARKWEB_LIBRARY_OPEN_FAILURE);
}

/**
 * @tc.name  : OH_ArkWebCookieManager_FetchCookieAsync_01
 * @tc.desc  : Test OH_ArkWebCookieManager_FetchCookieAsync
 */
HWTEST_F(NativeInterfaceArkWebTest, OH_ArkWebCookieManager_FetchCookieAsync_01, TestSize.Level1) {
    OH_ArkWeb_OnCookieFetchCallback callback = nullptr;
    g_errorCode = ArkWeb_ErrorCode::ARKWEB_SUCCESS;
    OH_ArkWebCookieManager_FetchCookieAsync("", false, false, false, callback);
    EXPECT_EQ(g_errorCode, ArkWeb_ErrorCode::ARKWEB_SUCCESS);

    g_errorCode = ArkWeb_ErrorCode::ARKWEB_SUCCESS;
    callback = OH_ArkWeb_OnCookieFetchCallbackImpl;
    OH_ArkWebCookieManager_FetchCookieAsync("", false, false, false, callback);
    EXPECT_EQ(g_errorCode, ArkWeb_ErrorCode::ARKWEB_LIBRARY_OPEN_FAILURE);
}

namespace {
char* DummyProxyCallback(const char** argv, int32_t argc)
{
    return nullptr;
}

void DummyValidCallback(const char* webTag) {}

void DummyDestroyCallback(const char* webTag) {}
} // namespace

/**
 * @tc.name  : OH_NativeArkWeb_RunJavaScript_02
 * @tc.desc  : Test OH_NativeArkWeb_RunJavaScript null params and valid web instance
 */
HWTEST_F(NativeInterfaceArkWebTest, OH_NativeArkWeb_RunJavaScript_02, TestSize.Level1)
{
    OH_NativeArkWeb_RunJavaScript(nullptr, "jsCode", nullptr);
    OH_NativeArkWeb_RunJavaScript("webTag", nullptr, nullptr);

    auto nweb = std::make_shared<OHOS::NWeb::FullMockNWeb>();
    OH_NativeArkWeb_BindWebTagToWebInstance("runJsTag", nweb);
    OH_NativeArkWeb_RunJavaScript("runJsTag", "jsCode", nullptr);
    EXPECT_EQ(nweb->executeJsCount, 1);
    OH_NativeArkWeb_BindWebTagToWebInstance("runJsTag", std::weak_ptr<OHOS::NWeb::NWeb>());
    OH_NativeArkWeb_RunJavaScript("runJsTag", "jsCode", nullptr);
    EXPECT_EQ(nweb->executeJsCount, 1);
}

/**
 * @tc.name  : OH_NativeArkWeb_RegisterJavaScriptProxy_02
 * @tc.desc  : Test OH_NativeArkWeb_RegisterJavaScriptProxy invalid params and valid web instance
 */
HWTEST_F(NativeInterfaceArkWebTest, OH_NativeArkWeb_RegisterJavaScriptProxy_02, TestSize.Level1)
{
    const char* methodName[PROXY_METHOD_COUNT] = { nullptr, "method2" };
    NativeArkWeb_OnJavaScriptProxyCallback callback[PROXY_METHOD_COUNT] = { DummyProxyCallback, nullptr };
    OH_NativeArkWeb_RegisterJavaScriptProxy(nullptr, "obj", methodName, callback, PROXY_METHOD_COUNT, false);
    OH_NativeArkWeb_RegisterJavaScriptProxy("webTag", nullptr, methodName, callback, PROXY_METHOD_COUNT, false);
    OH_NativeArkWeb_RegisterJavaScriptProxy("webTag", "obj", nullptr, callback, PROXY_METHOD_COUNT, false);
    OH_NativeArkWeb_RegisterJavaScriptProxy("webTag", "obj", methodName, nullptr, PROXY_METHOD_COUNT, false);
    OH_NativeArkWeb_RegisterJavaScriptProxy("webTag", "obj", methodName, callback, 0, false);
    OH_NativeArkWeb_RegisterJavaScriptProxy("webTag", "obj", methodName, callback, PROXY_METHOD_COUNT, false);

    auto nweb = std::make_shared<OHOS::NWeb::FullMockNWeb>();
    OH_NativeArkWeb_BindWebTagToWebInstance("proxyTag", nweb);
    OH_NativeArkWeb_RegisterJavaScriptProxy("proxyTag", "obj", methodName, callback, PROXY_METHOD_COUNT, true);
    EXPECT_EQ(nweb->registerNativeArkJSCount, 1);
    EXPECT_EQ(nweb->reloadCount, 1);
    OH_NativeArkWeb_RegisterJavaScriptProxy("proxyTag", "obj", methodName, callback, PROXY_METHOD_COUNT, false);
    EXPECT_EQ(nweb->registerNativeArkJSCount, PROXY_METHOD_COUNT);
    EXPECT_EQ(nweb->reloadCount, 1);

    const char* validMethods[PROXY_METHOD_COUNT] = { "method1", "method2" };
    NativeArkWeb_OnJavaScriptProxyCallback validCallbacks[PROXY_METHOD_COUNT] = { DummyProxyCallback,
        DummyProxyCallback };
    OH_NativeArkWeb_RegisterJavaScriptProxy("proxyTag", "obj", validMethods, validCallbacks, PROXY_METHOD_COUNT, false);
    EXPECT_EQ(nweb->registerNativeArkJSCount, 3);

    OH_NativeArkWeb_UnregisterJavaScriptProxy("proxyTag", "obj");
    EXPECT_EQ(nweb->unregisterNativeArkJSCount, 1);
    OH_NativeArkWeb_BindWebTagToWebInstance("proxyTag", std::weak_ptr<OHOS::NWeb::NWeb>());
}

/**
 * @tc.name  : OH_NativeArkWeb_DestroyCallback_02
 * @tc.desc  : Test destroy/valid callback set and get branches
 */
HWTEST_F(NativeInterfaceArkWebTest, OH_NativeArkWeb_DestroyCallback_02, TestSize.Level1)
{
    OH_NativeArkWeb_SetDestroyCallback(nullptr, nullptr);
    EXPECT_EQ(OH_NativeArkWeb_GetDestroyCallback(nullptr), nullptr);
    OH_NativeArkWeb_SetDestroyCallback("tagDestroy", DummyDestroyCallback);
    EXPECT_EQ(OH_NativeArkWeb_GetDestroyCallback("tagDestroy"), nullptr);

    OH_NativeArkWeb_SetJavaScriptProxyValidCallback(nullptr, nullptr);
    EXPECT_EQ(OH_NativeArkWeb_GetJavaScriptProxyValidCallback(nullptr), nullptr);
    OH_NativeArkWeb_SetJavaScriptProxyValidCallback("tagValid", DummyValidCallback);
    EXPECT_EQ(OH_NativeArkWeb_GetJavaScriptProxyValidCallback("tagValid"), DummyValidCallback);

    auto nweb = std::make_shared<OHOS::NWeb::FullMockNWeb>();
    OH_NativeArkWeb_BindWebTagToWebInstance("callbackTag", nweb);
    OH_NativeArkWeb_SetDestroyCallback("callbackTag", DummyDestroyCallback);
    EXPECT_EQ(nweb->registerDestroyCbCount, 1);
    EXPECT_EQ(OH_NativeArkWeb_GetDestroyCallback("callbackTag"), DummyDestroyCallback);
    OH_NativeArkWeb_SetJavaScriptProxyValidCallback("callbackTag", DummyValidCallback);
    EXPECT_EQ(nweb->registerValidCbCount, 1);
    OH_NativeArkWeb_BindWebTagToWebInstance("callbackTag", std::weak_ptr<OHOS::NWeb::NWeb>());
}

/**
 * @tc.name  : OH_NativeArkWeb_LoadData_01
 * @tc.desc  : Test OH_NativeArkWeb_LoadData and OH_NativeArkWeb_RegisterAsyncThreadJavaScriptProxy
 */
HWTEST_F(NativeInterfaceArkWebTest, OH_NativeArkWeb_LoadData_01, TestSize.Level1)
{
    auto savedEngine = OHOS::NWeb::NWebHelper::Instance().nwebEngine_;
    OHOS::NWeb::NWebHelper::Instance().nwebEngine_ = nullptr;
    EXPECT_EQ(OH_NativeArkWeb_LoadData("webTag", "data", "text/html", "utf-8", "", ""),
        ArkWeb_ErrorCode::ARKWEB_LIBRARY_OPEN_FAILURE);
    OH_NativeArkWeb_RegisterAsyncThreadJavaScriptProxy("webTag", nullptr, nullptr);

    auto engine = std::make_shared<OHOS::NWeb::FullMockNWebEngine>();
    OHOS::NWeb::NWebHelper::Instance().nwebEngine_ = engine;
    EXPECT_EQ(OH_NativeArkWeb_LoadData("webTag", "data", "text/html", "utf-8", "", ""),
        ArkWeb_ErrorCode::ARKWEB_LIBRARY_SYMBOL_NOT_FOUND);
    OH_NativeArkWeb_RegisterAsyncThreadJavaScriptProxy("webTag", nullptr, nullptr);

    char* cookie = nullptr;
    EXPECT_THAT(OH_ArkWebCookieManager_FetchCookieSync("url", false, false, false, &cookie),
        AnyOf(ArkWeb_ErrorCode::ARKWEB_LIBRARY_SYMBOL_NOT_FOUND, ArkWeb_ErrorCode::ARKWEB_LIBRARY_OPEN_FAILURE));
    OHOS::NWeb::NWebHelper::Instance().nwebEngine_ = savedEngine;
}

/**
 * @tc.name  : OH_ArkWebCookieManager_SaveCookie_02
 * @tc.desc  : Test cookie save with mock cookie manager
 */
HWTEST_F(NativeInterfaceArkWebTest, OH_ArkWebCookieManager_SaveCookie_02, TestSize.Level1)
{
    auto savedEngine = OHOS::NWeb::NWebHelper::Instance().nwebEngine_;
    auto engine = std::make_shared<OHOS::NWeb::FullMockNWebEngine>();
    auto cookieManager = std::make_shared<OHOS::NWeb::FullMockCookieManager>();
    engine->cookieManager_ = cookieManager;
    OHOS::NWeb::NWebHelper::Instance().nwebEngine_ = engine;

    cookieManager->storeResult = true;
    EXPECT_THAT(OH_ArkWebCookieManager_SaveCookieSync(),
        AnyOf(ArkWeb_ErrorCode::ARKWEB_SUCCESS, ArkWeb_ErrorCode::ARKWEB_COOKIE_MANAGER_INITIALIZE_FAILED));
    cookieManager->storeResult = false;
    EXPECT_THAT(OH_ArkWebCookieManager_SaveCookieSync(),
        AnyOf(ArkWeb_ErrorCode::ARKWEB_COOKIE_SAVE_FAILED, ArkWeb_ErrorCode::ARKWEB_COOKIE_MANAGER_INITIALIZE_FAILED));

    cookieManager->invokeCallback = true;
    cookieManager->storeResult = true;
    g_errorCode = ArkWeb_ErrorCode::ARKWEB_ERROR_UNKNOWN;
    OH_ArkWebCookieManager_SaveCookieAsync(OH_ArkWeb_OnCookieSaveCallbackImpl);
    EXPECT_THAT(g_errorCode,
        AnyOf(ArkWeb_ErrorCode::ARKWEB_SUCCESS, ArkWeb_ErrorCode::ARKWEB_COOKIE_MANAGER_INITIALIZE_FAILED));
    cookieManager->storeResult = false;
    OH_ArkWebCookieManager_SaveCookieAsync(OH_ArkWeb_OnCookieSaveCallbackImpl);
    EXPECT_THAT(g_errorCode,
        AnyOf(ArkWeb_ErrorCode::ARKWEB_COOKIE_SAVE_FAILED, ArkWeb_ErrorCode::ARKWEB_COOKIE_MANAGER_INITIALIZE_FAILED));
    OH_ArkWebCookieManager_SaveCookieAsync(nullptr);
    EXPECT_THAT(cookieManager->storeAsyncCount, AnyOf(3, 0));

    OHOS::NWeb::NWebHelper::Instance().nwebEngine_ = savedEngine;
}

/**
 * @tc.name  : OH_ArkWebCookieManager_Cookie_Thread_03
 * @tc.desc  : Test cookie apis from a non-main thread
 */
HWTEST_F(NativeInterfaceArkWebTest, OH_ArkWebCookieManager_Cookie_Thread_03, TestSize.Level1)
{
    auto savedEngine = OHOS::NWeb::NWebHelper::Instance().nwebEngine_;
    OHOS::NWeb::NWebHelper::Instance().nwebEngine_ = nullptr;

    ArkWeb_ErrorCode ret = ArkWeb_ErrorCode::ARKWEB_ERROR_UNKNOWN;
    std::thread t1([&ret]() { ret = OH_ArkWebCookieManager_SaveCookieSync(); });
    t1.join();
    EXPECT_EQ(ret, ArkWeb_ErrorCode::ARKWEB_COOKIE_MANAGER_NOT_INITIALIZED);

    std::thread t2([]() { OH_ArkWebCookieManager_SaveCookieAsync(OH_ArkWeb_OnCookieSaveCallbackImpl); });
    t2.join();
    std::thread t3([]() { OH_ArkWebCookieManager_SaveCookieAsync(nullptr); });
    t3.join();

    std::thread t4([]() {
        OH_ArkWebCookieManager_FetchCookieAsync("url", false, false, false, OH_ArkWeb_OnCookieFetchCallbackImpl);
    });
    t4.join();
    std::thread t5([]() { OH_ArkWebCookieManager_FetchCookieAsync(nullptr, false, false, false, nullptr); });
    t5.join();

    std::thread t6([&ret]() {
        char* cookie = nullptr;
        ret = OH_ArkWebCookieManager_FetchCookieSync("url", false, false, false, &cookie);
    });
    t6.join();
    EXPECT_EQ(ret, ArkWeb_ErrorCode::ARKWEB_COOKIE_MANAGER_NOT_INITIALIZED);

    OHOS::NWeb::NWebHelper::Instance().nwebEngine_ = savedEngine;
}

/**
 * @tc.name  : OH_NativeArkWeb_Blankless_M114_04
 * @tc.desc  : Test blankless apis when calling from M114 engine
 */
HWTEST_F(NativeInterfaceArkWebTest, OH_NativeArkWeb_Blankless_M114_04, TestSize.Level1)
{
    bool enabled = OHOS::system::GetBoolParameter("web.blankless.enabled", false);
    OHOS::system::SetParameter("web.blankless.enabled", "true");
    auto version = ArkWeb::getActiveWebEngineVersion();
    ArkWeb::setActiveWebEngineVersion(ArkWeb::ArkWebEngineVersion::M114);

    auto info = OH_NativeArkWeb_GetBlanklessInfoWithKey("webTag", "key");
    EXPECT_THAT(info.errCode, AnyOf(ArkWeb_BlanklessErrorCode::ARKWEB_BLANKLESS_ERR_DEVICE_NOT_SUPPORT, -1));
    EXPECT_THAT(OH_NativeArkWeb_SetBlanklessLoadingWithKey("webTag", "key", true),
        AnyOf(ArkWeb_BlanklessErrorCode::ARKWEB_BLANKLESS_ERR_DEVICE_NOT_SUPPORT, -1));
    const char* keys[] = { "key" };
    OH_NativeArkWeb_ClearBlanklessLoadingCache(keys, 1);
    EXPECT_THAT(OH_NativeArkWeb_SetBlanklessLoadingCacheCapacity(10), AnyOf(0, 10));

    ArkWeb::setActiveWebEngineVersion(version);
    OHOS::system::SetParameter("web.blankless.enabled", enabled ? "true" : "false");
}

/**
 * @tc.name  : OH_NativeArkWeb_Blankless_KeyTooLong_05
 * @tc.desc  : Test blankless apis with over-length key and mock engine
 */
HWTEST_F(NativeInterfaceArkWebTest, OH_NativeArkWeb_Blankless_KeyTooLong_05, TestSize.Level1)
{
    bool enabled = OHOS::system::GetBoolParameter("web.blankless.enabled", false);
    OHOS::system::SetParameter("web.blankless.enabled", "true");
    auto version = ArkWeb::getActiveWebEngineVersion();
    ArkWeb::setActiveWebEngineVersion(ArkWeb::ArkWebEngineVersion::M132);

    std::string longKey(3000, 'a');
    auto info = OH_NativeArkWeb_GetBlanklessInfoWithKey("webTag", longKey.c_str());
    EXPECT_EQ(info.errCode, ArkWeb_BlanklessErrorCode::ARKWEB_BLANKLESS_ERR_INVALID_ARGS);
    EXPECT_EQ(OH_NativeArkWeb_SetBlanklessLoadingWithKey("webTag", longKey.c_str(), true),
        ArkWeb_BlanklessErrorCode::ARKWEB_BLANKLESS_ERR_INVALID_ARGS);

    auto savedEngine = OHOS::NWeb::NWebHelper::Instance().nwebEngine_;
    auto engine = std::make_shared<OHOS::NWeb::FullMockNWebEngine>();
    OHOS::NWeb::NWebHelper::Instance().nwebEngine_ = engine;
    auto info1 = OH_NativeArkWeb_GetBlanklessInfoWithKey("webTag", "key");
    EXPECT_EQ(info1.errCode, ArkWeb_BlanklessErrorCode::ARKWEB_BLANKLESS_ERR_UNKNOWN);
    EXPECT_EQ(OH_NativeArkWeb_SetBlanklessLoadingWithKey("webTag", "key", true),
        ArkWeb_BlanklessErrorCode::ARKWEB_BLANKLESS_ERR_UNKNOWN);
    OHOS::NWeb::NWebHelper::Instance().nwebEngine_ = savedEngine;

    ArkWeb::setActiveWebEngineVersion(version);
    OHOS::system::SetParameter("web.blankless.enabled", enabled ? "true" : "false");
}

/**
 * @tc.name  : OH_ArkWebCookieManager_ThreadWithEngine_06
 * @tc.desc  : Test cookie apis from a non-main thread with web engine loaded
 */
HWTEST_F(NativeInterfaceArkWebTest, OH_ArkWebCookieManager_ThreadWithEngine_06, TestSize.Level1)
{
    auto savedEngine = OHOS::NWeb::NWebHelper::Instance().nwebEngine_;
    auto engine = std::make_shared<OHOS::NWeb::FullMockNWebEngine>();
    auto cookieManager = std::make_shared<OHOS::NWeb::FullMockCookieManager>();
    engine->cookieManager_ = cookieManager;
    OHOS::NWeb::NWebHelper::Instance().nwebEngine_ = engine;
    cookieManager->storeResult = true;

    ArkWeb_ErrorCode ret = ArkWeb_ErrorCode::ARKWEB_ERROR_UNKNOWN;
    std::thread t1([&ret]() { ret = OH_ArkWebCookieManager_SaveCookieSync(); });
    t1.join();
    EXPECT_THAT(
        ret, AnyOf(ArkWeb_ErrorCode::ARKWEB_SUCCESS, ArkWeb_ErrorCode::ARKWEB_COOKIE_MANAGER_INITIALIZE_FAILED));

    std::thread t2([]() { OH_ArkWebCookieManager_SaveCookieAsync(OH_ArkWeb_OnCookieSaveCallbackImpl); });
    t2.join();
    EXPECT_THAT(cookieManager->storeAsyncCount, AnyOf(1, 0));

    std::thread t3([&ret]() {
        char* cookie = nullptr;
        ret = OH_ArkWebCookieManager_FetchCookieSync("url", false, false, false, &cookie);
    });
    t3.join();
    EXPECT_THAT(
        ret, AnyOf(ArkWeb_ErrorCode::ARKWEB_LIBRARY_SYMBOL_NOT_FOUND, ArkWeb_ErrorCode::ARKWEB_LIBRARY_OPEN_FAILURE));

    g_errorCode = ArkWeb_ErrorCode::ARKWEB_ERROR_UNKNOWN;
    std::thread t4([]() {
        OH_ArkWebCookieManager_FetchCookieAsync("url", false, false, false, OH_ArkWeb_OnCookieFetchCallbackImpl);
    });
    t4.join();
    EXPECT_THAT(g_errorCode,
        AnyOf(ArkWeb_ErrorCode::ARKWEB_LIBRARY_SYMBOL_NOT_FOUND, ArkWeb_ErrorCode::ARKWEB_LIBRARY_OPEN_FAILURE));
    std::thread t5([]() { OH_ArkWebCookieManager_FetchCookieAsync("url", false, false, false, nullptr); });
    t5.join();

    OHOS::NWeb::NWebHelper::Instance().nwebEngine_ = savedEngine;
}

/**
 * @tc.name  : OH_ArkWebCookieManager_TaskRun_07
 * @tc.desc  : Run main event runner to execute posted cookie tasks
 */
HWTEST_F(NativeInterfaceArkWebTest, OH_ArkWebCookieManager_TaskRun_07, TestSize.Level1)
{
    auto savedEngine = OHOS::NWeb::NWebHelper::Instance().nwebEngine_;
    OHOS::NWeb::NWebHelper::Instance().nwebEngine_ = nullptr;

    auto runner = OHOS::AppExecFwk::EventRunner::GetMainEventRunner();
    ASSERT_NE(runner, nullptr);
    auto handler = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);

    // post save/fetch tasks from non-main threads with engine not loaded
    g_errorCode = ArkWeb_ErrorCode::ARKWEB_ERROR_UNKNOWN;
    std::thread t1([]() { OH_ArkWebCookieManager_SaveCookieAsync(OH_ArkWeb_OnCookieSaveCallbackImpl); });
    t1.join();
    std::thread t2([]() { OH_ArkWebCookieManager_SaveCookieAsync(nullptr); });
    t2.join();

    handler->PostTask([runner]() { runner->Stop(); }, "stopTask1", 200);
    runner->Run();
    // save lambda ran with null cookie manager
    EXPECT_EQ(g_errorCode, ArkWeb_ErrorCode::ARKWEB_COOKIE_MANAGER_INITIALIZE_FAILED);

    g_errorCode = ArkWeb_ErrorCode::ARKWEB_ERROR_UNKNOWN;
    std::thread t3([]() {
        OH_ArkWebCookieManager_FetchCookieAsync("url", false, false, false, OH_ArkWeb_OnCookieFetchCallbackImpl);
    });
    t3.join();
    std::thread t4([]() { OH_ArkWebCookieManager_FetchCookieAsync(nullptr, false, false, false, nullptr); });
    t4.join();
    handler->PostTask([runner]() { runner->Stop(); }, "stopTask2", 200);
    runner->Run();
    EXPECT_EQ(g_errorCode, ArkWeb_ErrorCode::ARKWEB_LIBRARY_OPEN_FAILURE);

    // cookie manager available in the posted task
    auto engine = std::make_shared<OHOS::NWeb::FullMockNWebEngine>();
    auto cookieManager = std::make_shared<OHOS::NWeb::FullMockCookieManager>();
    cookieManager->storeResult = true;
    cookieManager->invokeCallback = true;
    engine->cookieManager_ = cookieManager;
    OHOS::NWeb::NWebHelper::Instance().nwebEngine_ = engine;

    g_errorCode = ArkWeb_ErrorCode::ARKWEB_ERROR_UNKNOWN;
    std::thread t5([]() { OH_ArkWebCookieManager_SaveCookieAsync(OH_ArkWeb_OnCookieSaveCallbackImpl); });
    t5.join();
    handler->PostTask([runner]() { runner->Stop(); }, "stopTask3", 200);
    runner->Run();
    EXPECT_THAT(g_errorCode,
        AnyOf(ArkWeb_ErrorCode::ARKWEB_SUCCESS, ArkWeb_ErrorCode::ARKWEB_COOKIE_MANAGER_INITIALIZE_FAILED));

    OHOS::NWeb::NWebHelper::Instance().nwebEngine_ = savedEngine;
}

} // namespace NWeb
} // namespace OHOS
