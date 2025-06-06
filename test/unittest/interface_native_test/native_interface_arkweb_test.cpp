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
#include "interface/sdk_c/web/webview/interfaces/native/native_interface_arkweb.h"
#include "base/web/webview/interfaces/native/native_javascript_execute_callback.h"

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

} // namespace NWeb
} // namesapce OHOS