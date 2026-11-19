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
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "iremote_stub.h"
#include "location_callback_adapter_impl.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::NWeb {
class LocationCallbackAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void LocationCallbackAdapterTest::SetUpTestCase(void) {}

void LocationCallbackAdapterTest::TearDownTestCase(void) {}

void LocationCallbackAdapterTest::SetUp(void) {}

void LocationCallbackAdapterTest::TearDown(void) {}

class LocationCallbackAdapterMock : public LocationCallbackAdapter {
public:
    LocationCallbackAdapterMock() = default;

    void OnLocationReport(const std::shared_ptr<LocationInfo> location) override {}

    void OnLocatingStatusChange(const int status) override {}

    void OnErrorReport(const int errorCode) override {}
};

class CountingLocationCallbackAdapter : public LocationCallbackAdapter {
public:
    CountingLocationCallbackAdapter() = default;

    void OnLocationReport(const std::shared_ptr<LocationInfo> location) override
    {
        ++reportCount;
    }

    void OnLocatingStatusChange(const int status) override
    {
        ++statusCount;
    }

    void OnErrorReport(const int errorCode) override
    {
        ++errorCount;
    }

    int reportCount = 0;
    int statusCount = 0;
    int errorCount = 0;
};

/**
 * @tc.name: LocationCallbackAdapterTest_GetInstance_001
 * @tc.desc: OnRemoteRequest.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocationCallbackAdapterTest, LocationCallbackAdapterTest_GetInstance_001, TestSize.Level1)
{
    std::shared_ptr<LocationCallbackAdapter> adapter = std::make_shared<LocationCallbackAdapterMock>();
    EXPECT_NE(adapter, nullptr);
    auto locationImpl = std::make_shared<LocationCallbackImpl>(adapter);
    EXPECT_NE(locationImpl, nullptr);
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    std::u16string name = locationImpl->GetDescriptor();
    data.WriteInterfaceToken(name);
    uint32_t code = 0;
    int result = locationImpl->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, -1);
    code += 1;
    data.WriteInterfaceToken(name);
    result = locationImpl->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, -1);
    code += 1;
    data.WriteInterfaceToken(name);
    result = locationImpl->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, 0);
    code += 1;
    data.WriteInterfaceToken(name);
    result = locationImpl->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, 0);

    std::unique_ptr<OHOS::Location::Location> location = std::make_unique<OHOS::Location::Location>();
    EXPECT_NE(location, nullptr);
    locationImpl->OnLocationReport(location);
    locationImpl->OnLocatingStatusChange(0);
    locationImpl->OnErrorReport(0);
}

/**
 * @tc.name: LocationCallbackAdapterTest_GetInstance_002
 * @tc.desc: OnRemoteRequest.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocationCallbackAdapterTest, LocationCallbackAdapterTest_GetInstance_002, TestSize.Level1)
{
    auto locationImpl = std::make_shared<LocationCallbackImpl>(nullptr);
    EXPECT_NE(locationImpl, nullptr);
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    uint32_t code = 0;
    int result = locationImpl->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, -1);
    std::u16string name = locationImpl->GetDescriptor();
    data.WriteInterfaceToken(name);
    result = locationImpl->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, -1);

    std::unique_ptr<OHOS::Location::Location> location = std::make_unique<OHOS::Location::Location>();
    EXPECT_NE(location, nullptr);
    locationImpl->OnLocationReport(location);
    locationImpl->OnLocatingStatusChange(0);
    locationImpl->OnErrorReport(0);
}

/**
 * @tc.name: LocationCallbackAdapterTest_DetachedState_003
 * @tc.desc: MarkDetached/IsDetached.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocationCallbackAdapterTest, LocationCallbackAdapterTest_DetachedState_003, TestSize.Level1)
{
    std::shared_ptr<LocationCallbackAdapter> adapter = std::make_shared<LocationCallbackAdapterMock>();
    auto locationImpl = std::make_shared<LocationCallbackImpl>(adapter);
    EXPECT_FALSE(locationImpl->IsDetached());
    locationImpl->MarkDetached();
    EXPECT_TRUE(locationImpl->IsDetached());
}

/**
 * @tc.name: LocationCallbackAdapterTest_DetachedSkipsCallbacks_004
 * @tc.desc: Callbacks are ignored after the callback is detached.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocationCallbackAdapterTest, LocationCallbackAdapterTest_DetachedSkipsCallbacks_004, TestSize.Level1)
{
    auto adapter = std::make_shared<CountingLocationCallbackAdapter>();
    auto locationImpl = std::make_shared<LocationCallbackImpl>(adapter);
    locationImpl->MarkDetached();

    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    data.WriteInterfaceToken(locationImpl->GetDescriptor());
    EXPECT_EQ(locationImpl->OnRemoteRequest(0, data, reply, option), -1);

    std::unique_ptr<OHOS::Location::Location> location = std::make_unique<OHOS::Location::Location>();
    locationImpl->OnLocationReport(location);
    locationImpl->OnLocatingStatusChange(0);
    locationImpl->OnErrorReport(0);

    EXPECT_EQ(adapter->reportCount, 0);
    EXPECT_EQ(adapter->statusCount, 0);
    EXPECT_EQ(adapter->errorCount, 0);
}

/**
 * @tc.name: LocationCallbackAdapterTest_NotDetachedForwards_005
 * @tc.desc: Callbacks are forwarded when the callback is not detached.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocationCallbackAdapterTest, LocationCallbackAdapterTest_NotDetachedForwards_005, TestSize.Level1)
{
    auto adapter = std::make_shared<CountingLocationCallbackAdapter>();
    auto locationImpl = std::make_shared<LocationCallbackImpl>(adapter);
    EXPECT_FALSE(locationImpl->IsDetached());

    std::unique_ptr<OHOS::Location::Location> location = std::make_unique<OHOS::Location::Location>();
    locationImpl->OnLocationReport(location);
    locationImpl->OnLocatingStatusChange(0);
    locationImpl->OnErrorReport(0);

    EXPECT_EQ(adapter->reportCount, 1);
    EXPECT_EQ(adapter->statusCount, 1);
    EXPECT_EQ(adapter->errorCount, 1);
}
} // namespace OHOS
