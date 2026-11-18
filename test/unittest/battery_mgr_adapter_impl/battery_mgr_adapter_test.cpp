/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <cstring>
#include <gtest/gtest.h>

#define private public
#include "battery_mgr_client_adapter_impl.h"
#undef private

#include "battery_srv_client.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace EventFwk;
using namespace OHOS::EventFwk;
using namespace PowerMgr;

namespace OHOS {
namespace {
bool g_subscribeCommonEventRet = true;
bool g_unSubscribeCommonEventRet = true;
BatteryPluggedType g_pluggedType = BatteryPluggedType::PLUGGED_TYPE_NONE;
int32_t g_capacity = 100;
} // namespace

namespace EventFwk {
bool CommonEventManager::SubscribeCommonEvent(const std::shared_ptr<CommonEventSubscriber> &subscriber)
{
    return g_subscribeCommonEventRet;
}

bool CommonEventManager::UnSubscribeCommonEvent(const std::shared_ptr<CommonEventSubscriber> &subscriber)
{
    return g_unSubscribeCommonEventRet;
}
}
namespace PowerMgr {
BatteryPluggedType BatterySrvClient::GetPluggedType()
{
    return g_pluggedType;
}

int32_t BatterySrvClient::GetCapacity()
{
    return g_capacity;
}
}
namespace NWeb {
namespace {
std::shared_ptr<NWeb::NWebBatteryEventSubscriber> g_batter;
std::shared_ptr<NWeb::BatteryMgrClientAdapterImpl> g_batterImpl;
} // namespace

class MockWebBatteryEventCallback : public WebBatteryEventCallback {
public:
    MockWebBatteryEventCallback() = default;
    void BatteryInfoChanged(std::shared_ptr<WebBatteryInfo>) {};
};

class RecordingBatteryEventCallback : public WebBatteryEventCallback {
public:
    void BatteryInfoChanged(std::shared_ptr<WebBatteryInfo> info) override
    {
        ++callCount;
        if (info == nullptr) {
            return;
        }
        lastLevel = info->GetLevel();
        lastCharging = info->IsCharging();
        lastDisChargingTime = info->DisChargingTime();
        lastChargingTime = info->ChargingTime();
    }

    int32_t callCount = 0;
    double lastLevel = -1.0;
    bool lastCharging = false;
    int lastDisChargingTime = 0;
    int lastChargingTime = 0;
};

class BatteryMgrAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void BatteryMgrAdapterTest::SetUpTestCase(void)
{
    bool result = true;
    CommonEventSubscribeInfo subscribe;

    std::shared_ptr<WebBatteryEventCallback> eventCallback = std::make_shared<MockWebBatteryEventCallback>();
    g_batter = std::make_shared<NWebBatteryEventSubscriber>(subscribe, eventCallback);
    if (g_batter == nullptr) {
        result = false;
    }
    EXPECT_TRUE(result);
    g_batterImpl = std::make_shared<BatteryMgrClientAdapterImpl>();
    if (g_batter == nullptr) {
        result = false;
    }
    EXPECT_TRUE(result);
}

void BatteryMgrAdapterTest::TearDownTestCase(void)
{}

void BatteryMgrAdapterTest::SetUp(void)
{}

void BatteryMgrAdapterTest::TearDown(void)
{}

/**
 * @tc.name: BatteryAdapter_OnReceiveEvent_001.
 * @tc.desc: Test the OnReceiveEvent.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BatteryMgrAdapterTest, BatteryAdapter_OnReceiveEvent_001, TestSize.Level1)
{
    Want want;
    want.SetAction(CommonEventSupport::COMMON_EVENT_BATTERY_CHANGED);
    CommonEventData data(want);
    std::string key = PowerMgr::BatteryInfo::COMMON_EVENT_KEY_PLUGGED_TYPE;
    EXPECT_NE(g_batter, nullptr);
    g_batter->OnReceiveEvent(data);

    Want want1;
    want1.SetParam(key, static_cast<int>(BatteryPluggedType::PLUGGED_TYPE_NONE));
    CommonEventData data1(want1);
    g_batter->OnReceiveEvent(data1);
    Want wantEvent;
    wantEvent.SetParam(key, static_cast<int>(BatteryPluggedType::PLUGGED_TYPE_BUTT));
    CommonEventData dataEvent(wantEvent);
    g_batter->OnReceiveEvent(dataEvent);
}

/**
 * @tc.name: BatteryAdapter_RegBatteryEvent_002.
 * @tc.desc: Test the RegBatteryEvent.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BatteryMgrAdapterTest, BatteryAdapter_RegBatteryEvent_002, TestSize.Level1)
{
    std::shared_ptr<WebBatteryEventCallback> eventCallback = std::make_shared<MockWebBatteryEventCallback>();
    EXPECT_NE(g_batterImpl, nullptr);
    g_batterImpl->RegBatteryEvent(std::move(eventCallback));
    g_batterImpl->RegBatteryEvent(nullptr);
}

/**
 * @tc.name: BatteryAdapter_StartListen_003.
 * @tc.desc: Test the StartListen.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BatteryMgrAdapterTest, BatteryAdapter_StartListen_003, TestSize.Level1)
{
    bool result = g_batterImpl->StartListen();
    EXPECT_TRUE(result);
    g_subscribeCommonEventRet = false;
    result = g_batterImpl->StartListen();
    EXPECT_FALSE(result);
    g_subscribeCommonEventRet = true;
}

/**
 * @tc.name: BatteryAdapter_StopListen_004.
 * @tc.desc: Test the StopListen.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BatteryMgrAdapterTest, BatteryAdapter_StopListen_004, TestSize.Level1)
{
    g_unSubscribeCommonEventRet = false;
    EXPECT_NE(g_batterImpl, nullptr);
    g_batterImpl->StopListen();
    g_unSubscribeCommonEventRet = true;
    g_batterImpl->StopListen();
}

/**
 * @tc.name: BatteryAdapter_RequestBatteryInfo_005.
 * @tc.desc: Test the RequestBatteryInfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BatteryMgrAdapterTest, BatteryAdapter_RequestBatteryInfo_005, TestSize.Level1)
{
    bool result = true;
    g_pluggedType = BatteryPluggedType::PLUGGED_TYPE_AC;
    std::shared_ptr<WebBatteryInfo> battery = g_batterImpl->RequestBatteryInfo();
    if (battery == nullptr) {
        result = false;
    }
    EXPECT_TRUE(result);
    g_pluggedType = BatteryPluggedType::PLUGGED_TYPE_NONE;
    battery = g_batterImpl->RequestBatteryInfo();
    if (battery == nullptr) {
        result = false;
    }
    EXPECT_TRUE(result);
    g_pluggedType = BatteryPluggedType::PLUGGED_TYPE_BUTT;
    battery = g_batterImpl->RequestBatteryInfo();
    if (battery == nullptr) {
        result = false;
    }
    EXPECT_TRUE(result);
}

/**
 * @tc.name: BatteryAdapter_WebBatteryInfoImpl_006.
 * @tc.desc: Test the WebBatteryInfoImpl.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BatteryMgrAdapterTest, BatteryAdapter_WebBatteryInfoImpl_006, TestSize.Level1)
{
    double level = 1;
    bool isCharging = true;
    int disChargingTime = 1;
    int chargingTime = 1;
    WebBatteryInfoImpl info(level, isCharging, disChargingTime, chargingTime);
    EXPECT_FLOAT_EQ(info.GetLevel(), level);
    EXPECT_TRUE(info.IsCharging());
    EXPECT_EQ(info.DisChargingTime(), disChargingTime);
    EXPECT_EQ(info.ChargingTime(), chargingTime);
    Want want;
    want.SetAction(CommonEventSupport::COMMON_EVENT_BATTERY_LOW);
    CommonEventData data(want);
    g_batter->OnReceiveEvent(data);
    g_batterImpl->commonEventSubscriber_ = nullptr;
    g_batterImpl->StopListen();
}

/**
 * @tc.name: OnReceiveEvent_002
 * @tc.desc: Verify battery event parsing, charging state mapping and callback filtering
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BatteryMgrAdapterTest, OnReceiveEvent_002, TestSize.Level1)
{
    auto callback = std::make_shared<RecordingBatteryEventCallback>();
    CommonEventSubscribeInfo subscribe;
    NWebBatteryEventSubscriber subscriber(subscribe, callback);

    Want want;
    want.SetAction(CommonEventSupport::COMMON_EVENT_BATTERY_CHANGED);
    want.SetParam(PowerMgr::BatteryInfo::COMMON_EVENT_KEY_CAPACITY, 50);
    want.SetParam(PowerMgr::BatteryInfo::COMMON_EVENT_KEY_PLUGGED_TYPE,
        static_cast<int>(BatteryPluggedType::PLUGGED_TYPE_AC));
    CommonEventData data(want);
    subscriber.OnReceiveEvent(data);
    EXPECT_EQ(callback->callCount, 1);
    EXPECT_DOUBLE_EQ(callback->lastLevel, 0.5);
    EXPECT_TRUE(callback->lastCharging);
    EXPECT_EQ(callback->lastDisChargingTime, -1);
    EXPECT_EQ(callback->lastChargingTime, -1);

    Want wantUnplugged;
    wantUnplugged.SetAction(CommonEventSupport::COMMON_EVENT_BATTERY_CHANGED);
    wantUnplugged.SetParam(PowerMgr::BatteryInfo::COMMON_EVENT_KEY_CAPACITY, 100);
    wantUnplugged.SetParam(PowerMgr::BatteryInfo::COMMON_EVENT_KEY_PLUGGED_TYPE,
        static_cast<int>(BatteryPluggedType::PLUGGED_TYPE_NONE));
    CommonEventData unpluggedData(wantUnplugged);
    subscriber.OnReceiveEvent(unpluggedData);
    EXPECT_EQ(callback->callCount, 2);
    EXPECT_DOUBLE_EQ(callback->lastLevel, 1.0);
    EXPECT_FALSE(callback->lastCharging);

    Want wantOtherAction;
    wantOtherAction.SetAction(CommonEventSupport::COMMON_EVENT_BATTERY_LOW);
    CommonEventData otherData(wantOtherAction);
    subscriber.OnReceiveEvent(otherData);
    EXPECT_EQ(callback->callCount, 2);

    NWebBatteryEventSubscriber noCallbackSubscriber(subscribe, nullptr);
    noCallbackSubscriber.OnReceiveEvent(data);
    EXPECT_EQ(callback->callCount, 2);
}

/**
 * @tc.name: RequestBatteryInfo_002
 * @tc.desc: Verify RequestBatteryInfo converts capacity and plugged type correctly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BatteryMgrAdapterTest, RequestBatteryInfo_002, TestSize.Level1)
{
    g_capacity = 50;
    g_pluggedType = BatteryPluggedType::PLUGGED_TYPE_AC;
    auto info = g_batterImpl->RequestBatteryInfo();
    ASSERT_NE(info, nullptr);
    EXPECT_DOUBLE_EQ(info->GetLevel(), 0.5);
    EXPECT_TRUE(info->IsCharging());

    g_pluggedType = BatteryPluggedType::PLUGGED_TYPE_BUTT;
    info = g_batterImpl->RequestBatteryInfo();
    ASSERT_NE(info, nullptr);
    EXPECT_FALSE(info->IsCharging());

    g_capacity = 100;
    g_pluggedType = BatteryPluggedType::PLUGGED_TYPE_NONE;
}

/**
 * @tc.name: WebBatteryInfoImpl_002
 * @tc.desc: Verify WebBatteryInfoImpl getters with zero and negative boundary values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BatteryMgrAdapterTest, WebBatteryInfoImpl_002, TestSize.Level2)
{
    WebBatteryInfoImpl info(0.0, false, -1, -1);
    EXPECT_DOUBLE_EQ(info.GetLevel(), 0.0);
    EXPECT_FALSE(info.IsCharging());
    EXPECT_EQ(info.DisChargingTime(), -1);
    EXPECT_EQ(info.ChargingTime(), -1);
}

/**
 * @tc.name: StartListen_002
 * @tc.desc: Verify StartListen fails when no event callback has been registered
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BatteryMgrAdapterTest, StartListen_002, TestSize.Level2)
{
    BatteryMgrClientAdapterImpl adapter;
    EXPECT_FALSE(adapter.StartListen());
}

/**
 * @tc.name: StopListen_002
 * @tc.desc: Verify StopListen keeps subscriber on unsubscribe failure and clears it on retry
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BatteryMgrAdapterTest, StopListen_002, TestSize.Level2)
{
    auto callback = std::make_shared<MockWebBatteryEventCallback>();
    BatteryMgrClientAdapterImpl adapter;
    adapter.RegBatteryEvent(callback);
    ASSERT_TRUE(adapter.StartListen());
    ASSERT_NE(adapter.commonEventSubscriber_, nullptr);

    g_unSubscribeCommonEventRet = false;
    adapter.StopListen();
    EXPECT_NE(adapter.commonEventSubscriber_, nullptr);

    g_unSubscribeCommonEventRet = true;
    adapter.StopListen();
    EXPECT_EQ(adapter.commonEventSubscriber_, nullptr);
}

/**
 * @tc.name: OnReceiveEvent_003
 * @tc.desc: Verify missing capacity and plugged-type params fall back to defaults
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BatteryMgrAdapterTest, OnReceiveEvent_003, TestSize.Level2)
{
    auto callback = std::make_shared<RecordingBatteryEventCallback>();
    CommonEventSubscribeInfo subscribe;
    NWebBatteryEventSubscriber subscriber(subscribe, callback);

    Want want;
    want.SetAction(CommonEventSupport::COMMON_EVENT_BATTERY_CHANGED);
    CommonEventData data(want);
    subscriber.OnReceiveEvent(data);

    EXPECT_EQ(callback->callCount, 1);
    EXPECT_DOUBLE_EQ(callback->lastLevel, -0.01);
    EXPECT_TRUE(callback->lastCharging);
    EXPECT_EQ(callback->lastDisChargingTime, -1);
    EXPECT_EQ(callback->lastChargingTime, -1);
}

/**
 * @tc.name: OnReceiveEvent_004
 * @tc.desc: Verify zero capacity maps to level zero and BUTT plug type maps to not charging
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BatteryMgrAdapterTest, OnReceiveEvent_004, TestSize.Level2)
{
    auto callback = std::make_shared<RecordingBatteryEventCallback>();
    CommonEventSubscribeInfo subscribe;
    NWebBatteryEventSubscriber subscriber(subscribe, callback);

    Want want;
    want.SetAction(CommonEventSupport::COMMON_EVENT_BATTERY_CHANGED);
    want.SetParam(PowerMgr::BatteryInfo::COMMON_EVENT_KEY_CAPACITY, 0);
    want.SetParam(PowerMgr::BatteryInfo::COMMON_EVENT_KEY_PLUGGED_TYPE,
        static_cast<int>(BatteryPluggedType::PLUGGED_TYPE_BUTT));
    CommonEventData data(want);
    subscriber.OnReceiveEvent(data);

    EXPECT_EQ(callback->callCount, 1);
    EXPECT_DOUBLE_EQ(callback->lastLevel, 0.0);
    EXPECT_FALSE(callback->lastCharging);
}

/**
 * @tc.name: RegBatteryEvent_003
 * @tc.desc: Verify null registration keeps the previous callback and re-registration overwrites it
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BatteryMgrAdapterTest, RegBatteryEvent_003, TestSize.Level2)
{
    auto first = std::make_shared<RecordingBatteryEventCallback>();
    auto second = std::make_shared<RecordingBatteryEventCallback>();
    BatteryMgrClientAdapterImpl adapter;
    adapter.RegBatteryEvent(first);
    adapter.RegBatteryEvent(nullptr);
    ASSERT_TRUE(adapter.StartListen());

    auto subscriber = std::static_pointer_cast<NWebBatteryEventSubscriber>(adapter.commonEventSubscriber_);
    ASSERT_NE(subscriber, nullptr);
    Want want;
    want.SetAction(CommonEventSupport::COMMON_EVENT_BATTERY_CHANGED);
    want.SetParam(PowerMgr::BatteryInfo::COMMON_EVENT_KEY_CAPACITY, 30);
    CommonEventData data(want);
    subscriber->OnReceiveEvent(data);
    EXPECT_EQ(first->callCount, 1);
    EXPECT_DOUBLE_EQ(first->lastLevel, 0.3);

    adapter.RegBatteryEvent(second);
    ASSERT_TRUE(adapter.StartListen());
    subscriber = std::static_pointer_cast<NWebBatteryEventSubscriber>(adapter.commonEventSubscriber_);
    ASSERT_NE(subscriber, nullptr);
    subscriber->OnReceiveEvent(data);
    EXPECT_EQ(first->callCount, 1);
    EXPECT_EQ(second->callCount, 1);
    EXPECT_DOUBLE_EQ(second->lastLevel, 0.3);

    adapter.StopListen();
}

/**
 * @tc.name: StartListen_003
 * @tc.desc: Verify repeated StartListen replaces the subscriber and failed subscribe clears it
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BatteryMgrAdapterTest, StartListen_003, TestSize.Level2)
{
    auto callback = std::make_shared<MockWebBatteryEventCallback>();
    BatteryMgrClientAdapterImpl adapter;
    adapter.RegBatteryEvent(callback);

    ASSERT_TRUE(adapter.StartListen());
    auto firstSubscriber = adapter.commonEventSubscriber_;
    ASSERT_NE(firstSubscriber, nullptr);
    EXPECT_TRUE(adapter.StartListen());
    EXPECT_NE(firstSubscriber, adapter.commonEventSubscriber_);

    g_subscribeCommonEventRet = false;
    EXPECT_FALSE(adapter.StartListen());
    EXPECT_EQ(adapter.commonEventSubscriber_, nullptr);
    g_subscribeCommonEventRet = true;

    adapter.StopListen();
}

/**
 * @tc.name: RequestBatteryInfo_003
 * @tc.desc: Verify zero capacity maps to level zero while AC plug keeps charging
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BatteryMgrAdapterTest, RequestBatteryInfo_003, TestSize.Level2)
{
    g_capacity = 0;
    g_pluggedType = BatteryPluggedType::PLUGGED_TYPE_AC;
    auto info = g_batterImpl->RequestBatteryInfo();
    ASSERT_NE(info, nullptr);
    EXPECT_DOUBLE_EQ(info->GetLevel(), 0.0);
    EXPECT_TRUE(info->IsCharging());

    g_capacity = 100;
    g_pluggedType = BatteryPluggedType::PLUGGED_TYPE_NONE;
}

/**
 * @tc.name: Destructor_001
 * @tc.desc: Verify destructor unsubscribes the active listener without crashing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BatteryMgrAdapterTest, Destructor_001, TestSize.Level2)
{
    auto callback = std::make_shared<MockWebBatteryEventCallback>();

    BatteryMgrClientAdapterImpl* adapter = new BatteryMgrClientAdapterImpl();
    adapter->RegBatteryEvent(callback);
    ASSERT_TRUE(adapter->StartListen());
    EXPECT_NO_THROW(delete adapter);

    BatteryMgrClientAdapterImpl* failingAdapter = new BatteryMgrClientAdapterImpl();
    failingAdapter->RegBatteryEvent(callback);
    ASSERT_TRUE(failingAdapter->StartListen());
    g_unSubscribeCommonEventRet = false;
    EXPECT_NO_THROW(delete failingAdapter);
    g_unSubscribeCommonEventRet = true;
}

/**
 * @tc.name: WebBatteryInfoImpl_003
 * @tc.desc: Verify getters return raw stored values without clamping at boundaries
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BatteryMgrAdapterTest, WebBatteryInfoImpl_003, TestSize.Level2)
{
    WebBatteryInfoImpl zero(0.0, false, 0, 0);
    EXPECT_DOUBLE_EQ(zero.GetLevel(), 0.0);
    EXPECT_FALSE(zero.IsCharging());
    EXPECT_EQ(zero.DisChargingTime(), 0);
    EXPECT_EQ(zero.ChargingTime(), 0);

    WebBatteryInfoImpl outOfRange(2.5, true, -100, 200);
    EXPECT_DOUBLE_EQ(outOfRange.GetLevel(), 2.5);
    EXPECT_TRUE(outOfRange.IsCharging());
    EXPECT_EQ(outOfRange.DisChargingTime(), -100);
    EXPECT_EQ(outOfRange.ChargingTime(), 200);
}
}
}
