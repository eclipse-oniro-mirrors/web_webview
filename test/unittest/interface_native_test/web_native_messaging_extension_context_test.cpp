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

#define private public
#define protected public
#include <memory>

#include "ability_manager_client.h"
#include "ipc_types.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "iremote_stub.h"
#include "nocopyable.h"
#include "want.h"
#include "web_native_messaging_client.h"
#include "web_native_messaging_extension_context.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::NWeb;
using namespace OHOS::AAFwk;

class ITestAbilityToken : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"test.web.ITestAbilityToken");
    virtual int Test() = 0;
};

class TestAbilityToken : public IRemoteStub<ITestAbilityToken> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override
    {
        return 0;
    }

    int Test() override
    {
        return 0;
    }
};

class WebNativeMessagingContextTest : public testing::Test {
public:
    void SetUp() override
    {
        context_ = std::make_unique<WebNativeMessagingExtensionContext>();
        token_ = sptr<IRemoteObject>(new TestAbilityToken());
        context_->SetToken(token_);
        want_ = std::make_shared<Want>();
        want_->SetElementName("com.test", "TestAbility");
    }

    void TearDown() override
    {
        context_.reset();
        token_ = nullptr;
        want_.reset();
    }

protected:
    std::unique_ptr<WebNativeMessagingExtensionContext> context_;
    sptr<IRemoteObject> token_;
    std::shared_ptr<Want> want_;
    StartOptions startOpts_;
};

/**
 * @tc.name: WebNativeMessagingContextTest.StartAbility_Success
 * @tc.desc: Test StartAbility method with successful case
 * @tc.type: FUNC
 */
HWTEST_F(WebNativeMessagingContextTest, StartAbility_Success, TestSize.Level1)
{
    EXPECT_NE(context_->token_, nullptr) << "Token should be set";
    ErrCode result = context_->StartAbility(*want_, startOpts_);
    // The native messaging SA(8610) is dynamically loaded on demand. When the SA is
    // available (e.g. RK), the client returns the business error PERMISSION_CHECK_ERROR;
    // when the SA load times out (e.g. 7885), the proxy is null and IPC_ERROR is returned.
    if (result == ConnectNativeRet::IPC_ERROR) {
        EXPECT_EQ(result, ConnectNativeRet::IPC_ERROR) << "Actual result: " << result;
    } else {
        EXPECT_EQ(result, ConnectNativeRet::PERMISSION_CHECK_ERROR) << "Actual result: " << result;
    }
}

/**
 * @tc.name: WebNativeMessagingContextTest.StartAbility_Fail
 * @tc.desc: Test StartAbility method with failure case
 * @tc.type: FUNC
 */
HWTEST_F(WebNativeMessagingContextTest, StartAbility_Fail, TestSize.Level1)
{
    EXPECT_NE(context_->token_, nullptr) << "Token should be set";
    ErrCode result = context_->StartAbility(*want_, startOpts_);
    // See StartAbility_Success: the return value depends on whether SA(8610) is loaded.
    if (result == ConnectNativeRet::IPC_ERROR) {
        EXPECT_EQ(result, ConnectNativeRet::IPC_ERROR) << "Actual result: " << result;
    } else {
        EXPECT_EQ(result, ConnectNativeRet::PERMISSION_CHECK_ERROR) << "Actual result: " << result;
    }
}

/**
 * @tc.name: WebNativeMessagingContextTest.StopNativeConnection_Success
 * @tc.desc: Test StopNativeConnection method with valid connection ID
 * @tc.type: FUNC
 */
HWTEST_F(WebNativeMessagingContextTest, StopNativeConnection_Success, TestSize.Level1)
{
    ErrCode result = context_->StopNativeConnection(100);
    // When SA(8610) is available, CONNECTION_NOT_EXIST is returned for the unknown
    // connection id; when SA load times out, IPC_ERROR is returned instead.
    if (result == ConnectNativeRet::IPC_ERROR) {
        EXPECT_EQ(result, ConnectNativeRet::IPC_ERROR) << "Actual result: " << result;
    } else {
        EXPECT_EQ(result, ConnectNativeRet::CONNECTION_NOT_EXIST) << "Actual result: " << result;
    }
}

/**
 * @tc.name: WebNativeMessagingContextTest.StopNativeConnection_Fail
 * @tc.desc: Test StopNativeConnection method with invalid connection ID
 * @tc.type: FUNC
 */
HWTEST_F(WebNativeMessagingContextTest, StopNativeConnection_Fail, TestSize.Level1)
{
    ErrCode result = context_->StopNativeConnection(-1);
    // See StopNativeConnection_Success: return value depends on whether SA(8610) is loaded.
    if (result == ConnectNativeRet::IPC_ERROR) {
        EXPECT_EQ(result, ConnectNativeRet::IPC_ERROR) << "Actual result: " << result;
    } else {
        EXPECT_EQ(result, ConnectNativeRet::CONNECTION_NOT_EXIST) << "Actual result: " << result;
    }
}

/**
 * @tc.name: WebNativeMessagingContextTest.TerminateSelf_Success
 * @tc.desc: Test TerminateSelf method with successful case
 * @tc.type: FUNC
 */
HWTEST_F(WebNativeMessagingContextTest, TerminateSelf_Success, TestSize.Level1)
{
    EXPECT_NE(context_->token_, nullptr) << "Token should be set";
    ErrCode result = context_->TerminateSelf();
    EXPECT_EQ(result, 22) << "Actual result: " << result;
}

/**
 * @tc.name: WebNativeMessagingContextTest.TerminateSelf_Fail
 * @tc.desc: Test TerminateSelf method with failure case
 * @tc.type: FUNC
 */
HWTEST_F(WebNativeMessagingContextTest, TerminateSelf_Fail, TestSize.Level1)
{
    EXPECT_NE(context_->token_, nullptr) << "Token should be set";
    ErrCode result = context_->TerminateSelf();
    EXPECT_EQ(result, 22) << "Actual result: " << result;
}
