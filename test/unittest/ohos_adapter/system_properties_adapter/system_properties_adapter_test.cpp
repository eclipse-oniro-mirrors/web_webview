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

#include "system_properties_adapter_impl.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::NWeb {
class SystemPropertiesAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void SystemPropertiesAdapterTest::SetUpTestCase(void)
{}

void SystemPropertiesAdapterTest::TearDownTestCase(void)
{}

void SystemPropertiesAdapterTest::SetUp(void)
{}

void SystemPropertiesAdapterTest::TearDown(void)
{}

/**
 * @tc.name: SystemPropertiesAdapterTest_GetDeviceInfoBrand_001
 * @tc.desc: GetInstance.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SystemPropertiesAdapterTest, SystemPropertiesAdapterTest_GetDeviceInfoBrand_001, TestSize.Level1)
{
    std::string model = SystemPropertiesAdapterImpl::GetInstance().GetDeviceInfoProductModel();
    EXPECT_NE(model, "");
    std::string deviceInfo = SystemPropertiesAdapterImpl::GetInstance().GetDeviceInfoBrand();
    EXPECT_NE(deviceInfo, "");
    int32_t result = SystemPropertiesAdapterImpl::GetInstance().GetDeviceInfoMajorVersion();
    EXPECT_NE(result, -1);
    SystemPropertiesAdapterImpl::GetInstance().GetResourceUseHapPathEnable();
    SystemPropertiesAdapterImpl::GetInstance().GetProductDeviceType();
    bool value = SystemPropertiesAdapterImpl::GetInstance().GetWebOptimizationValue();
    EXPECT_TRUE(value);
    system("param set web.optimization false");
    value = SystemPropertiesAdapterImpl::GetInstance().GetWebOptimizationValue();
    EXPECT_FALSE(value);
    system("param set web.optimization true");
    bool mode = SystemPropertiesAdapterImpl::GetInstance().IsAdvancedSecurityMode();
    EXPECT_FALSE(mode);
    string logMode = SystemPropertiesAdapterImpl::GetInstance().GetNetlogMode();
    EXPECT_EQ(logMode, "None");
    string siteIsolationMode = SystemPropertiesAdapterImpl::GetInstance().GetSiteIsolationMode();
    EXPECT_EQ(siteIsolationMode, "none");
}
} // namespace OHOS
