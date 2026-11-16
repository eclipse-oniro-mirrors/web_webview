/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "accesstoken_kit.h"

#define private public
#include "net_conn_client_test_mock.h"
#include "net_proxy_adapter_impl.h"
#include "token_setproc.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AAFwk;
using namespace OHOS::NetManagerStandard;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::EventFwk;

namespace OHOS {
namespace {
bool g_subscribeCommonEventRet = true;
bool g_unSubscribeCommonEventRet = true;
} // namespace
namespace EventFwk {
bool CommonEventManager::SubscribeCommonEvent(const std::shared_ptr<CommonEventSubscriber>& subscriber)
{
    return g_subscribeCommonEventRet;
}

bool CommonEventManager::UnSubscribeCommonEvent(const std::shared_ptr<CommonEventSubscriber>& subscriber)
{
    return g_unSubscribeCommonEventRet;
}
} // namespace EventFwk
} // namespace OHOS

namespace OHOS::NWeb {
namespace {
using Security::AccessToken::AccessTokenID;
using namespace Security::AccessToken;

HapInfoParams testInfoParms = {
    .userID = 1,
    .bundleName = "web_conn_manager_test",
    .instIndex = 0,
    .appIDDesc = "test",
    .isSystemApp = true,
};

PermissionDef testPermDef = {
    .permissionName = "ohos.permission.GET_NETWORK_INFO",
    .bundleName = "web_conn_manager_test",
    .grantMode = 1,
    .label = "label",
    .labelId = 1,
    .description = "Test web connect maneger",
    .descriptionId = 1,
    .availableLevel = APL_SYSTEM_BASIC,
};

PermissionDef testInternalPermDef = {
    .permissionName = "ohos.permission.CONNECTIVITY_INTERNAL",
    .bundleName = "web_conn_manager_test",
    .grantMode = 1,
    .availableLevel = APL_SYSTEM_BASIC,
    .label = "label",
    .labelId = 1,
    .description = "Test web connect manager internal",
    .descriptionId = 1,
};

PermissionDef testInternetPermDef = {
    .permissionName = "ohos.permission.INTERNET",
    .bundleName = "web_conn_manager_test",
    .grantMode = 1,
    .availableLevel = APL_SYSTEM_BASIC,
    .label = "label",
    .labelId = 1,
    .description = "Test web connect manager internet",
    .descriptionId = 1,
};

PermissionStateFull testState = {
    .grantFlags = { 2 },
    .grantStatus = { PermissionState::PERMISSION_GRANTED },
    .isGeneral = true,
    .permissionName = "ohos.permission.GET_NETWORK_INFO",
    .resDeviceID = { "local" },
};

PermissionStateFull testInternalState = {
    .permissionName = "ohos.permission.CONNECTIVITY_INTERNAL",
    .isGeneral = true,
    .resDeviceID = { "local" },
    .grantStatus = { PermissionState::PERMISSION_GRANTED },
    .grantFlags = { 2 },
};

PermissionStateFull testInternetState = {
    .permissionName = "ohos.permission.INTERNET",
    .isGeneral = true,
    .resDeviceID = { "local" },
    .grantStatus = { PermissionState::PERMISSION_GRANTED },
    .grantFlags = { 2 },
};

HapPolicyParams testPolicyPrams = {
    .apl = APL_SYSTEM_BASIC,
    .domain = "test.domain",
    .permList = { testPermDef, testInternalPermDef, testInternetPermDef },
    .permStateList = { testState, testInternalState, testInternetState },
};
} // namespace

class NetProxyAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void NetProxyAdapterTest::SetUpTestCase(void) {}

void NetProxyAdapterTest::TearDownTestCase(void) {}

void NetProxyAdapterTest::SetUp(void) {}

void NetProxyAdapterTest::TearDown(void) {}

class AccessToken {
public:
    AccessToken() : currentID_(GetSelfTokenID())
    {
        AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(testInfoParms, testPolicyPrams);
        accessID_ = tokenIdEx.tokenIdExStruct.tokenID;
        SetSelfTokenID(tokenIdEx.tokenIDEx);
    }
    ~AccessToken()
    {
        AccessTokenKit::DeleteToken(accessID_);
        SetSelfTokenID(currentID_);
    }

private:
    AccessTokenID currentID_;
    AccessTokenID accessID_ = 0;
};

class MockNetProxyEventCallbackAdapter : public NetProxyEventCallbackAdapter {
public:
    MockNetProxyEventCallbackAdapter() = default;
    void Changed(const std::string& host, const uint16_t& port, const std::string& pacUrl,
        const std::vector<std::string>& exclusionList)
    {
        host_ = std::move(host);
        port_ = port;
        std::string httpProxyExclusions;
        for (const auto& s : exclusionList) {
            httpProxyExclusions.append(s + ",");
        }
        if (!httpProxyExclusions.empty()) {
            httpProxyExclusions.pop_back();
        }
        exclusion_ = httpProxyExclusions;
    }

    std::string host_;
    uint16_t port_;
    std::string exclusion_;
};

/**
 * @tc.name: NetProxyAdapterTest_StartListen_001.
 * @tc.desc: IMF adapter unittest.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NetProxyAdapterTest, NetProxyAdapterTest_StartListen_001, TestSize.Level1)
{
    ASSERT_FALSE(NetProxyAdapterImpl::GetInstance().StartListen());

    std::shared_ptr<MockNetProxyEventCallbackAdapter> eventCallback =
        std::make_shared<MockNetProxyEventCallbackAdapter>();
    NetProxyAdapterImpl::GetInstance().RegNetProxyEvent(eventCallback);
    HttpProxy httpProxy("NONE", 1, { "exclusion1", "exclusion2" });
    NetConnClientMock::SetDefaultHttpProxy(httpProxy);
    NetConnClientMock::SetAppId(1);
    ASSERT_TRUE(NetProxyAdapterImpl::GetInstance().StartListen());
    ASSERT_TRUE(NetConnClientMock::IsAppExist(1));
    EXPECT_EQ(eventCallback->host_, "");
    EXPECT_EQ(eventCallback->port_, 1);
    EXPECT_EQ(eventCallback->exclusion_, "exclusion1,exclusion2");
    ASSERT_TRUE(NetProxyAdapterImpl::GetInstance().StartListen());

    NetProxyAdapterImpl::GetInstance().StopListen();
    ASSERT_FALSE(NetConnClientMock::IsAppExist(1));
}

/**
 * @tc.name: NetProxyAdapterTest_GetProperty_002.
 * @tc.desc: IMF adapter unittest.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NetProxyAdapterTest, NetProxyAdapterTest_GetProperty_002, TestSize.Level1)
{
    std::string host;
    uint16_t port;
    std::string pacUrl;
    std::string exclusion;
    HttpProxy httpProxy("testHost", 1, { "exclusion1", "exclusion2" });
    NetConnClientMock::SetDefaultHttpProxy(httpProxy);
    NetProxyAdapterImpl::GetInstance().GetProperty(host, port, pacUrl, exclusion);
    EXPECT_EQ(host, "testHost");
    EXPECT_EQ(port, 1);
    EXPECT_EQ(exclusion, "exclusion1,exclusion2");

    httpProxy = HttpProxy("NONE", 0, { "NONE" });
    NetConnClientMock::SetDefaultHttpProxy(httpProxy);
    NetProxyAdapterImpl::GetInstance().GetProperty(host, port, pacUrl, exclusion);
    EXPECT_EQ(host, "");
    EXPECT_EQ(port, 0);
    EXPECT_EQ(exclusion, "");
}

/**
 * @tc.name: NetProxyAdapterTest_OnReceiveEvent_003.
 * @tc.desc: IMF adapter unittest.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NetProxyAdapterTest, NetProxyAdapterTest_OnReceiveEvent_003, TestSize.Level1)
{
    EventFwk::MatchingSkills skill = EventFwk::MatchingSkills();
    EventFwk::CommonEventSubscribeInfo info(skill);
    std::shared_ptr<MockNetProxyEventCallbackAdapter> eventCallback =
        std::make_shared<MockNetProxyEventCallbackAdapter>();
    NetProxyEventSubscriber criber(info, eventCallback);

    HttpProxy httpProxy("testHost", 1, { "exclusion1", "exclusion2" });
    NetConnClientMock::SetDefaultHttpProxy(httpProxy);
    EventFwk::CommonEventData data;
    criber.OnReceiveEvent(data);
    EXPECT_EQ(eventCallback->host_, "");
    EXPECT_EQ(eventCallback->port_, 0);
    EXPECT_EQ(eventCallback->exclusion_, "");

    Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_HTTP_PROXY_CHANGE);
    data.SetWant(want);
    criber.OnReceiveEvent(data);
    EXPECT_EQ(eventCallback->host_, "testHost");
    EXPECT_EQ(eventCallback->port_, 1);
    EXPECT_EQ(eventCallback->exclusion_, "exclusion1,exclusion2");
}

/**
 * @tc.name: NetProxyAdapterTest_Encode_004.
 * @tc.desc: IMF adapter unittest.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NetProxyAdapterTest, NetProxyAdapterTest_Encode_004, TestSize.Level1)
{
    std::string source = "";
    std::string result = Base64::Encode(source);
    EXPECT_TRUE(result.empty());
    result = Base64::Decode(source);
    EXPECT_TRUE(result.empty());
    source = "++webtest";
    Base64::Decode(source);
    source = "webtest++++++";
    Base64::Decode(source);
    result = Base64::Encode(source);
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: NetProxyAdapterTest_Base64_005.
 * @tc.desc: Cover IsBase64Char slash and invalid char branches.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NetProxyAdapterTest, NetProxyAdapterTest_Base64_005, TestSize.Level1)
{
    // '/' is a base64 char though it is neither alnum nor '+'.
    std::string result = Base64::Decode("ab/d");
    EXPECT_FALSE(result.empty());
    // '=' is not a base64 char, decode stops at it.
    result = Base64::Decode("ab=c");
    EXPECT_EQ(result.size(), 1);
    // encode a two-byte tail to cover the padding branches.
    result = Base64::Encode("ab");
    EXPECT_EQ(result, "YWI=");
}

/**
 * @tc.name: NetProxyAdapterTest_RegNetProxyEvent_006.
 * @tc.desc: RegNetProxyEvent with null callback.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NetProxyAdapterTest, NetProxyAdapterTest_RegNetProxyEvent_006, TestSize.Level1)
{
    NetProxyAdapterImpl::GetInstance().RegNetProxyEvent(nullptr);
    std::shared_ptr<MockNetProxyEventCallbackAdapter> eventCallback =
        std::make_shared<MockNetProxyEventCallbackAdapter>();
    NetProxyAdapterImpl::GetInstance().RegNetProxyEvent(eventCallback);
    EXPECT_NE(NetProxyAdapterImpl::GetInstance().cb_, nullptr);
}

/**
 * @tc.name: NetProxyAdapterTest_Changed_007.
 * @tc.desc: Changed with listening flag reset and valid callback.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NetProxyAdapterTest, NetProxyAdapterTest_Changed_007, TestSize.Level1)
{
    std::shared_ptr<MockNetProxyEventCallbackAdapter> eventCallback =
        std::make_shared<MockNetProxyEventCallbackAdapter>();
    NetProxyAdapterImpl::GetInstance().RegNetProxyEvent(eventCallback);
    NetProxyAdapterImpl::GetInstance().listen_ = false;
    HttpProxy httpProxy("testHost", 8080, { "exclusion1" });
    NetConnClientMock::SetDefaultHttpProxy(httpProxy);
    NetConnClientMock::SetDefaultHttpProxyResult(0);
    NetProxyAdapterImpl::GetInstance().Changed();
    EXPECT_EQ(eventCallback->host_, "testHost");
    EXPECT_EQ(eventCallback->port_, 8080);
}

/**
 * @tc.name: NetProxyAdapterTest_StartListenFail_008.
 * @tc.desc: StartListen when subscribe common event fails.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NetProxyAdapterTest, NetProxyAdapterTest_StartListenFail_008, TestSize.Level1)
{
    std::shared_ptr<MockNetProxyEventCallbackAdapter> eventCallback =
        std::make_shared<MockNetProxyEventCallbackAdapter>();
    NetProxyAdapterImpl::GetInstance().RegNetProxyEvent(eventCallback);
    NetConnClientMock::SetDefaultHttpProxy(HttpProxy("NONE", 1, { "NONE" }));
    NetConnClientMock::SetDefaultHttpProxyResult(0);
    NetProxyAdapterImpl::GetInstance().commonEventSubscriber_ = nullptr;
    g_subscribeCommonEventRet = false;
    ASSERT_FALSE(NetProxyAdapterImpl::GetInstance().StartListen());
    g_subscribeCommonEventRet = true;
}

/**
 * @tc.name: NetProxyAdapterTest_StopListen_009.
 * @tc.desc: StopListen with null subscriber and failed unsubscribe.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NetProxyAdapterTest, NetProxyAdapterTest_StopListen_009, TestSize.Level1)
{
    NetProxyAdapterImpl::GetInstance().commonEventSubscriber_ = nullptr;
    NetProxyAdapterImpl::GetInstance().StopListen();

    std::shared_ptr<MockNetProxyEventCallbackAdapter> eventCallback =
        std::make_shared<MockNetProxyEventCallbackAdapter>();
    NetProxyAdapterImpl::GetInstance().RegNetProxyEvent(eventCallback);
    NetProxyAdapterImpl::GetInstance().commonEventSubscriber_ = nullptr;
    NetConnClientMock::SetDefaultHttpProxy(HttpProxy("NONE", 1, { "NONE" }));
    NetConnClientMock::SetDefaultHttpProxyResult(0);
    ASSERT_TRUE(NetProxyAdapterImpl::GetInstance().StartListen());

    g_unSubscribeCommonEventRet = false;
    NetProxyAdapterImpl::GetInstance().StopListen();
    EXPECT_NE(NetProxyAdapterImpl::GetInstance().commonEventSubscriber_, nullptr);
    g_unSubscribeCommonEventRet = true;
    NetProxyAdapterImpl::GetInstance().StopListen();
    EXPECT_EQ(NetProxyAdapterImpl::GetInstance().commonEventSubscriber_, nullptr);
}

/**
 * @tc.name: NetProxyAdapterTest_StartListenAppProxy_010.
 * @tc.desc: Cover app proxy lambda branches.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NetProxyAdapterTest, NetProxyAdapterTest_StartListenAppProxy_010, TestSize.Level1)
{
    std::shared_ptr<MockNetProxyEventCallbackAdapter> eventCallback =
        std::make_shared<MockNetProxyEventCallbackAdapter>();
    NetProxyAdapterImpl::GetInstance().RegNetProxyEvent(eventCallback);

    // app proxy host is not empty: default proxy is not queried.
    NetConnClientMock::SetAppHttpProxy(HttpProxy("appHost", 8080, { "ex1" }));
    EXPECT_EQ(NetConnClientMock::GetAppHttpProxy().GetHost(), "appHost");
    NetConnClientMock::SetAppId(10);
    NetProxyAdapterImpl::GetInstance().StartListenAppProxy();
    EXPECT_EQ(eventCallback->host_, "appHost");
    EXPECT_EQ(eventCallback->exclusion_, "ex1");
    NetProxyAdapterImpl::GetInstance().StopListen();

    // app proxy host is empty and GetDefaultHttpProxy fails.
    NetConnClientMock::SetAppHttpProxy(HttpProxy("", 0, {}));
    EXPECT_EQ(NetConnClientMock::GetAppHttpProxy().GetHost(), "");
    NetConnClientMock::SetDefaultHttpProxyResult(-1);
    NetConnClientMock::SetAppId(11);
    NetProxyAdapterImpl::GetInstance().StartListenAppProxy();
    NetProxyAdapterImpl::GetInstance().StopListen();

    // app proxy host is empty, default proxy host is valid.
    NetConnClientMock::SetDefaultHttpProxy(HttpProxy("defaultHost", 1080, {}));
    NetConnClientMock::SetDefaultHttpProxyResult(0);
    NetConnClientMock::SetAppId(12);
    NetProxyAdapterImpl::GetInstance().StartListenAppProxy();
    EXPECT_EQ(eventCallback->host_, "defaultHost");
    NetProxyAdapterImpl::GetInstance().StopListen();

    // callback is null when the app proxy callback fires.
    NetProxyAdapterImpl::GetInstance().RegNetProxyEvent(nullptr);
    NetConnClientMock::SetAppId(13);
    NetProxyAdapterImpl::GetInstance().StartListenAppProxy();
    NetProxyAdapterImpl::GetInstance().StopListen();
    NetProxyAdapterImpl::GetInstance().RegNetProxyEvent(eventCallback);
    NetConnClientMock::SetDefaultHttpProxyResult(0);
}

/**
 * @tc.name: NetProxyAdapterTest_OnReceiveEvent_011.
 * @tc.desc: OnReceiveEvent with proxy query failure, null callback and empty exclusions.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NetProxyAdapterTest, NetProxyAdapterTest_OnReceiveEvent_011, TestSize.Level1)
{
    EventFwk::MatchingSkills skill = EventFwk::MatchingSkills();
    EventFwk::CommonEventSubscribeInfo info(skill);
    std::shared_ptr<MockNetProxyEventCallbackAdapter> eventCallback =
        std::make_shared<MockNetProxyEventCallbackAdapter>();
    NetProxyEventSubscriber criber(info, eventCallback);

    Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_HTTP_PROXY_CHANGE);
    EventFwk::CommonEventData data;
    data.SetWant(want);

    // GetDefaultHttpProxy fails.
    NetConnClientMock::SetDefaultHttpProxyResult(-1);
    criber.OnReceiveEvent(data);
    EXPECT_EQ(eventCallback->host_, "");
    NetConnClientMock::SetDefaultHttpProxyResult(0);

    // event callback is null.
    NetProxyEventSubscriber criberNullCb(info, nullptr);
    criberNullCb.OnReceiveEvent(data);

    // exclusion list is empty.
    NetConnClientMock::SetDefaultHttpProxy(HttpProxy("testHost", 1, {}));
    criber.OnReceiveEvent(data);
    EXPECT_EQ(eventCallback->host_, "testHost");
    EXPECT_EQ(eventCallback->exclusion_, "");
}

/**
 * @tc.name: NetProxyAdapterTest_GetPropertyFail_012.
 * @tc.desc: GetProperty when GetDefaultHttpProxy fails.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NetProxyAdapterTest, NetProxyAdapterTest_GetPropertyFail_012, TestSize.Level1)
{
    std::string host;
    uint16_t port = 1;
    std::string pacUrl;
    std::string exclusion;
    NetConnClientMock::SetDefaultHttpProxyResult(-1);
    NetProxyAdapterImpl::GetInstance().GetProperty(host, port, pacUrl, exclusion);
    EXPECT_EQ(host, "");
    EXPECT_EQ(port, 0);
    EXPECT_EQ(exclusion, "");
    NetConnClientMock::SetDefaultHttpProxyResult(0);
}
} // namespace OHOS::NWeb
