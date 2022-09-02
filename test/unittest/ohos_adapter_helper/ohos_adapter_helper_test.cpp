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

#include "ohos_adapter_helper.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::NWeb {
class OhosAdapterHelperTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void OhosAdapterHelperTest::SetUpTestCase(void)
{}

void OhosAdapterHelperTest::TearDownTestCase(void)
{}

void OhosAdapterHelperTest::SetUp(void)
{}

void OhosAdapterHelperTest::TearDown(void)
{}

/**
 * @tc.name: OhosAdapterHelper_GetInstance_001.
 * @tc.desc: Test the GetInstance.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(OhosAdapterHelperTest, OhosAdapterHelper_GetInstance_001, TestSize.Level1)
{
    OhosAdapterHelper &helper = OhosAdapterHelper::GetInstance();
    std::unique_ptr<AafwkAppMgrClientAdapter> client = helper.CreateAafwkAdapter();
    EXPECT_NE(client, nullptr);
    std::unique_ptr<PowerMgrClientAdapter> powerMgr = helper.CreatePowerMgrClientAdapter();
    EXPECT_NE(powerMgr, nullptr);
    std::unique_ptr<DisplayManagerAdapter> display = helper.CreateDisplayMgrAdapter();
    EXPECT_NE(display, nullptr);
    std::unique_ptr<BatteryMgrClientAdapter> battery = helper.CreateBatteryClientAdapter();
    EXPECT_NE(battery, nullptr);
    helper.GetOhosWebDataBaseAdapterInstance();
    std::unique_ptr<NetConnectAdapter> connect = helper.CreateNetConnectAdapter();
    EXPECT_NE(connect, nullptr);
    helper.GetPasteBoard();
    std::unique_ptr<AudioRendererAdapter> audioRender = helper.CreateAudioRendererAdapter();
    EXPECT_NE(audioRender, nullptr);
    helper.GetAudioSystemManager();
    helper.GetWebPermissionDataBaseInstance();
    std::unique_ptr<MMIAdapter> mmiAdapter = helper.CreateMMIAdapter();
    EXPECT_NE(mmiAdapter, nullptr);
}
}