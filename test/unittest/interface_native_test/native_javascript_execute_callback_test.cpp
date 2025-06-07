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

#define private public
#include "base/web/webview/interfaces/native/native_javascript_execute_callback.h"
#include "base/web/webview/ohos_interface/include/ohos_nweb/nweb_hap_value.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace NWeb {

class TmpHapValue : public OHOS::NWeb::NWebHapValue {
public:
    explicit TmpHapValue(OHOS::NWeb::NWebHapValue::Type type) : type_(type) {}
    ~TmpHapValue() {}

    OHOS::NWeb::NWebHapValue::Type GetType() { return type_; }

    void SetType(OHOS::NWeb::NWebHapValue::Type type) { type_ = type; }

    int GetInt() { return 0; }

    void SetInt(int value) {}

    bool GetBool() {return true; }

    void SetBool(bool value) {}

    double GetDouble() { return 0.0; }

    void SetDouble(double value) {}

    std::string GetString() { return str_; }

    void SetString(const std::string& value) { str_ = value; }

    const char* GetBinary(int& length) { return nullptr; }

    void SetBinary(int length, const char* value) {}

    std::map<std::string, std::shared_ptr<OHOS::NWeb::NWebHapValue>> GetDictValue() { return dict_; }

    std::vector<std::shared_ptr<OHOS::NWeb::NWebHapValue>> GetListValue() { return list_; }

    std::shared_ptr<OHOS::NWeb::NWebHapValue> NewChildValue() { return child_; }

    void SaveDictChildValue(const std::string& key) {}

    void SaveListChildValue() {}
private:
    OHOS::NWeb::NWebHapValue::Type type_;
    std::string str_;
    std::map<std::string, std::shared_ptr<OHOS::NWeb::NWebHapValue>> dict_;
    std::vector<std::shared_ptr<OHOS::NWeb::NWebHapValue>> list_;
    std::shared_ptr<OHOS::NWeb::NWebHapValue> child_;
};

class NativeJavascriptExecuteCallbackTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void NativeJavascriptExecuteCallbackTest::SetUpTestCase(void) {}

void NativeJavascriptExecuteCallbackTest::TearDownTestCase(void) {}

void NativeJavascriptExecuteCallbackTest::SetUp(void) {}

void NativeJavascriptExecuteCallbackTest::TearDown(void) {}

void CallbackNative(const char* message) {}

/**
 * @tc.name  : OHNativeJavascriptExecuteCallbackTest_OnReceiveValue_01
 * @tc.desc  : Test OnReceiveValue
 */
HWTEST_F(NativeJavascriptExecuteCallbackTest,
         OHNativeJavascriptExecuteCallbackTest_OnReceiveValue_01, TestSize.Level1) {
    std::function<void(const char*)> callback = nullptr;
    std::shared_ptr<NWebMessage> result = std::make_shared<NWebMessage>();
    NativeJavaScriptExecuteCallback nativeJSExecuteCallback(callback);
    nativeJSExecuteCallback.OnReceiveValue(result);
}

/**
 * @tc.name  : OHNativeJavascriptExecuteCallbackTest_OnReceiveValue_02
 * @tc.desc  : Test OnReceiveValue
 */
HWTEST_F(NativeJavascriptExecuteCallbackTest,
         OHNativeJavascriptExecuteCallbackTest_OnReceiveValue_02, TestSize.Level1) {
    std::function<void(const char*)> callback = CallbackNative;
    std::shared_ptr<NWebMessage> result = std::make_shared<NWebMessage>(NWebValue::Type::NONE);
    NativeJavaScriptExecuteCallback nativeJSExecuteCallback(callback);
    nativeJSExecuteCallback.OnReceiveValue(result);
}

/**
 * @tc.name  : OHNativeJavascriptExecuteCallbackTest_OnReceiveValue_03
 * @tc.desc  : Test OnReceiveValue
 */
HWTEST_F(NativeJavascriptExecuteCallbackTest,
         OHNativeJavascriptExecuteCallbackTest_OnReceiveValue_03, TestSize.Level1) {
    std::function<void(const char*)> callback = CallbackNative;
    NativeJavaScriptExecuteCallback nativeJSExecuteCallback(callback);
    std::shared_ptr<NWebMessage> result = std::make_shared<NWebMessage>(NWebValue::Type::STRING);
    result->SetString("test");
    nativeJSExecuteCallback.OnReceiveValue(result);
}

/**
 * @tc.name  : OHNativeJavascriptExecuteCallbackTest_OnReceiveValueV2_01
 * @tc.desc  : Test OnReceiveValueV2
 */
HWTEST_F(NativeJavascriptExecuteCallbackTest,
         OHNativeJavascriptExecuteCallbackTest_OnReceiveValueV2_01, TestSize.Level1) {
    std::function<void(const char*)> callback = nullptr;
    std::shared_ptr<OHOS::NWeb::NWebHapValue> result = nullptr;
    NativeJavaScriptExecuteCallback nativeJSExecuteCallback(callback);
    nativeJSExecuteCallback.OnReceiveValueV2(result);
}

/**
 * @tc.name  : OHNativeJavascriptExecuteCallbackTest_OnReceiveValueV2_02
 * @tc.desc  : Test OnReceiveValueV2
 */
HWTEST_F(NativeJavascriptExecuteCallbackTest,
         OHNativeJavascriptExecuteCallbackTest_OnReceiveValueV2_02, TestSize.Level1) {
    std::function<void(const char*)> callback = CallbackNative;
    NativeJavaScriptExecuteCallback nativeJSExecuteCallback(callback);
    std::shared_ptr<OHOS::NWeb::NWebHapValue> result =
        std::make_shared<TmpHapValue>(NWebHapValue::Type::NONE);
    nativeJSExecuteCallback.OnReceiveValueV2(result);
}

/**
 * @tc.name  : OHNativeJavascriptExecuteCallbackTest_OnReceiveValueV2_03
 * @tc.desc  : Test OnReceiveValueV2
 */
HWTEST_F(NativeJavascriptExecuteCallbackTest,
         OHNativeJavascriptExecuteCallbackTest_OnReceiveValueV2_03, TestSize.Level1) {
    std::function<void(const char*)> callback = CallbackNative;
    NativeJavaScriptExecuteCallback nativeJSExecuteCallback(callback);
    std::shared_ptr<OHOS::NWeb::NWebHapValue> result =
        std::make_shared<TmpHapValue>(NWebHapValue::Type::STRING);
    result->SetString("test");
    nativeJSExecuteCallback.OnReceiveValueV2(result);
}

} // namespace NWeb
} // namesapce OHOS