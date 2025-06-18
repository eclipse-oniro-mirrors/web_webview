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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <securec.h>

#define private public
#include "base/web/webview/interfaces/native/native_javascript_execute_callback.h"
#include "native_interface_arkweb.h"
#include "system_properties_adapter_impl.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace NWeb {

class NativeInterfaceArkWebTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void NativeInterfaceArkWebTest::SetUpTestCase(void) {}

void NativeInterfaceArkWebTest::TearDownTestCase(void) {}

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
    ProductDeviceType deviceType = SystemPropertiesAdapterImpl::GetInstance().GetProductDeviceType();
    bool isMobile = deviceType == ProductDeviceType::DEVICE_TYPE_MOBILE;
    auto info = OH_NativeArkWeb_GetBlanklessInfoWithKey("", "");
    EXPECT_EQ(info.errCode, isMobile ? ArkWeb_BlanklessErrorCode::ARKWEB_BLANKLESS_ERR_INVALID_ARGS
        : ArkWeb_BlanklessErrorCode::ARKWEB_BLANKLESS_ERR_DEVICE_NOT_SUPPORT);
    auto info1 = OH_NativeArkWeb_GetBlanklessInfoWithKey("", "OH_NativeArkWeb_GetBlanklessInfoWithKey");
    EXPECT_EQ(info1.errCode, isMobile ? ArkWeb_BlanklessErrorCode::ARKWEB_BLANKLESS_ERR_UNKNOWN
        : ArkWeb_BlanklessErrorCode::ARKWEB_BLANKLESS_ERR_DEVICE_NOT_SUPPORT);
}

/**
 * @tc.name  : OH_NativeArkWeb_SetBlanklessLoadingWithKey_01
 * @tc.desc  : Test OH_NativeArkWeb_SetBlanklessLoadingWithKey
 */
HWTEST_F(NativeInterfaceArkWebTest, OH_NativeArkWeb_SetBlanklessLoadingWithKey_01, TestSize.Level1) {
    ProductDeviceType deviceType = SystemPropertiesAdapterImpl::GetInstance().GetProductDeviceType();
    bool isMobile = deviceType == ProductDeviceType::DEVICE_TYPE_MOBILE;
    auto errCode = OH_NativeArkWeb_SetBlanklessLoadingWithKey("", "", true);
    EXPECT_EQ(errCode, isMobile ? ArkWeb_BlanklessErrorCode::ARKWEB_BLANKLESS_ERR_INVALID_ARGS
        : ArkWeb_BlanklessErrorCode::ARKWEB_BLANKLESS_ERR_DEVICE_NOT_SUPPORT);
    auto errCode1 = OH_NativeArkWeb_SetBlanklessLoadingWithKey("", "OH_NativeArkWeb_SetBlanklessLoadingWithKey", false);
    EXPECT_EQ(errCode1, isMobile ? ArkWeb_BlanklessErrorCode::ARKWEB_BLANKLESS_ERR_UNKNOWN
        : ArkWeb_BlanklessErrorCode::ARKWEB_BLANKLESS_ERR_DEVICE_NOT_SUPPORT);
}

/**
 * @tc.name  : OH_NativeArkWeb_ClearBlanklessLoadingCache_01
 * @tc.desc  : Test OH_NativeArkWeb_ClearBlanklessLoadingCache
 */
HWTEST_F(NativeInterfaceArkWebTest, OH_NativeArkWeb_ClearBlanklessLoadingCache_01, TestSize.Level1) {
    OH_NativeArkWeb_ClearBlanklessLoadingCache(nullptr, 0);
    const char* keys[] = {"ClearBlanklessLoadingCache1", "ClearBlanklessLoadingCache2"};
    OH_NativeArkWeb_ClearBlanklessLoadingCache(keys, 2);
    EXPECT_EQ(OH_NativeArkWeb_SetBlanklessLoadingCacheCapacity(0), 0); // UT contains at least one judgment statement
}

/**
 * @tc.name  : OH_NativeArkWeb_SetBlanklessLoadingCacheCapacity_01
 * @tc.desc  : Test OH_NativeArkWeb_SetBlanklessLoadingCacheCapacity
 */
HWTEST_F(NativeInterfaceArkWebTest, OH_NativeArkWeb_SetBlanklessLoadingCacheCapacity_01, TestSize.Level1) {
    ProductDeviceType deviceType = SystemPropertiesAdapterImpl::GetInstance().GetProductDeviceType();
    bool isMobile = deviceType == ProductDeviceType::DEVICE_TYPE_MOBILE;
    EXPECT_EQ(OH_NativeArkWeb_SetBlanklessLoadingCacheCapacity(20), isMobile ? 20 : 0);
    EXPECT_EQ(OH_NativeArkWeb_SetBlanklessLoadingCacheCapacity(100), isMobile ? 100 : 0);
    EXPECT_EQ(OH_NativeArkWeb_SetBlanklessLoadingCacheCapacity(1000), isMobile ? 100 : 0);
}
} // namespace NWeb
} // namesapce OHOS