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

#define private public
#include "net_proxy_adapter_impl.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AAFwk;

namespace OHOS::NWeb {

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

/**
 * @tc.name: NetProxyAdapterTest_OnReceiveEvent_001.
 * @tc.desc: IMF adapter unittest.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NetProxyAdapterTest, NetProxyAdapterTest_OnReceiveEvent_001, TestSize.Level1)
{
    EventFwk::MatchingSkills skill = EventFwk::MatchingSkills();
    EventFwk::CommonEventSubscribeInfo info(skill);
    NetProxyEventCallback eventCallback =
        [](std::string& host, uint16_t& port, const std::string& pacUrl,
        const std::vector<std::string>& exclusionList) {};
    NetProxyEventSubscriber criber(info, eventCallback);
    EXPECT_NE(criber.eventCallback_, nullptr);
    EventFwk::CommonEventData data;
    criber.OnReceiveEvent(data);
    Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_HTTP_PROXY_CHANGE);
    data.SetWant(want);
    criber.OnReceiveEvent(data);
}

/**
 * @tc.name: NetProxyAdapterTest_RegNetProxyEvent_002.
 * @tc.desc: IMF adapter unittest.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NetProxyAdapterTest, NetProxyAdapterTest_RegNetProxyEvent_002, TestSize.Level1)
{
    NetProxyAdapterImpl::GetInstance().RegNetProxyEvent(nullptr);
    EXPECT_EQ(NetProxyAdapterImpl::GetInstance().cb_, nullptr);
    bool result = NetProxyAdapterImpl::GetInstance().StartListen();
    EXPECT_FALSE(result);
    NetProxyEventCallback eventCallback =
        [](std::string& host, uint16_t& port, const std::string& pacUrl,
        const std::vector<std::string>& exclusionList) {};
    NetProxyAdapterImpl::GetInstance().RegNetProxyEvent(std::move(eventCallback));
    EXPECT_NE(NetProxyAdapterImpl::GetInstance().cb_, nullptr);
    result = NetProxyAdapterImpl::GetInstance().StartListen();
    EXPECT_TRUE(result);
}

/**
 * @tc.name: NetProxyAdapterTest_GetProperty_003.
 * @tc.desc: IMF adapter unittest.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NetProxyAdapterTest, NetProxyAdapterTest_GetProperty_003, TestSize.Level1)
{
    std::string host;
    uint16_t port;
    std::string pacUrl;
    std::string exclusion;
    NetProxyAdapterImpl::GetInstance().GetProperty(host, port, pacUrl, exclusion);
    EXPECT_NE(NetProxyAdapterImpl::GetInstance().commonEventSubscriber_, nullptr);
    NetProxyAdapterImpl::GetInstance().StopListen();
    NetProxyAdapterImpl::GetInstance().commonEventSubscriber_ = nullptr;
    NetProxyAdapterImpl::GetInstance().StopListen();
}
} // namespace OHOS::NWeb