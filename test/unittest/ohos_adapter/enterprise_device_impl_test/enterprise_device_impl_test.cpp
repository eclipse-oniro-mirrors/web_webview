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

#include <cstring>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "enterprise_device_management_adapter_impl.h"
#include "browser_proxy.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::EDM;

namespace OHOS {
namespace EDM {
namespace {
std::shared_ptr<BrowserProxy> g_browserProxy = nullptr;
} // namespace
std::shared_ptr<BrowserProxy> BrowserProxy::GetBrowserProxy()
{
    return g_browserProxy;
}
}

namespace NWeb {
class EnterpriseDeviceImplTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void EnterpriseDeviceImplTest::SetUpTestCase(void)
{}

void EnterpriseDeviceImplTest::TearDownTestCase(void)
{}

void EnterpriseDeviceImplTest::SetUp(void)
{}

void EnterpriseDeviceImplTest::TearDown(void)
{}

/**
 * @tc.name: EnterpriseDeviceImplTest_BackgroundTaskAdapter_001
 * @tc.desc: BackgroundTaskAdapter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EnterpriseDeviceImplTest, EnterpriseDeviceImplTest_BackgroundTaskAdapter_001, TestSize.Level1)
{
    std::string policies = "web_test";
    int32_t result = EnterpriseDeviceManagementAdapterImpl::GetInstance().GetPolicies(policies);
    EXPECT_EQ(result, -1);
    g_browserProxy = std::make_shared<BrowserProxy>();
    result = EnterpriseDeviceManagementAdapterImpl::GetInstance().GetPolicies(policies);
    EXPECT_EQ(result, 0);
}
}
} // namespace OHOS