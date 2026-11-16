/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "nweb_helper.h"
#include "nweb_user_agent_builder.h"

using namespace testing::ext;

namespace OHOS::NWeb {

class NwebUserAgentBuilderTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void NwebUserAgentBuilderTest::SetUpTestCase(void) {}

void NwebUserAgentBuilderTest::TearDownTestCase(void) {}

void NwebUserAgentBuilderTest::SetUp(void) {}

void NwebUserAgentBuilderTest::TearDown(void) {}

/**
 * @tc.name: NwebUserAgentBuilderTest_BuildUserAgentLite_001
 * @tc.desc: Mobile template is byte-identical to BR-1 (two spaces, " Mobile" suffix).
 */
HWTEST_F(NwebUserAgentBuilderTest, NwebUserAgentBuilderTest_BuildUserAgentLite_001, TestSize.Level1)
{
    UserAgentLiteParams params;
    params.deviceType = "Phone";
    params.osName = "OpenHarmony";
    params.osMajorVersion = 5;
    params.osSeniorVersion = 1;
    params.chromeCompatibleVersion = "144";
    params.arkWebVersion = "5.1.6.1";
    params.appendMobile = true;
    std::string ua = UserAgentBuilder::BuildUserAgentLite(params);
    EXPECT_EQ(ua,
        "Mozilla/5.0 (Phone; OpenHarmony 5.1) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/144.0.0.0 Safari/537.36  ArkWeb/5.1.6.1 Mobile");
}

/**
 * @tc.name: NwebUserAgentBuilderTest_BuildUserAgentLite_002
 * @tc.desc: Non-mobile string terminates at the version with no trailing spaces;
 *           exactly two spaces separate Safari/537.36 and ArkWeb/.
 */
HWTEST_F(NwebUserAgentBuilderTest, NwebUserAgentBuilderTest_BuildUserAgentLite_002, TestSize.Level1)
{
    UserAgentLiteParams params;
    params.deviceType = "Tablet";
    params.osName = "OpenHarmony";
    params.osMajorVersion = 5;
    params.osSeniorVersion = 1;
    params.chromeCompatibleVersion = "132";
    params.arkWebVersion = "4.1.6.1";
    params.appendMobile = false;
    std::string ua = UserAgentBuilder::BuildUserAgentLite(params);
    EXPECT_EQ(ua,
        "Mozilla/5.0 (Tablet; OpenHarmony 5.1) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/132.0.0.0 Safari/537.36  ArkWeb/4.1.6.1");
    EXPECT_NE(ua.find("Safari/537.36  ArkWeb/"), std::string::npos);
    EXPECT_EQ(ua.find("Safari/537.36   ArkWeb/"), std::string::npos);
    EXPECT_EQ(ua.back(), '1');
}

/**
 * @tc.name: NwebUserAgentBuilderTest_BuildUserAgentLite_003
 * @tc.desc: OS info fallback (empty osName / -1 versions) drops the version segment,
 *           matching the kernel GetOhosFullname fallback.
 */
HWTEST_F(NwebUserAgentBuilderTest, NwebUserAgentBuilderTest_BuildUserAgentLite_003, TestSize.Level1)
{
    UserAgentLiteParams params;
    params.deviceType = "PC";
    params.osName = "";
    params.osMajorVersion = -1;
    params.osSeniorVersion = -1;
    params.chromeCompatibleVersion = "114";
    params.arkWebVersion = "3.1.6.1";
    params.appendMobile = false;
    std::string ua = UserAgentBuilder::BuildUserAgentLite(params);
    EXPECT_EQ(ua,
        "Mozilla/5.0 (PC; OpenHarmony) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/114.0.0.0 Safari/537.36  ArkWeb/3.1.6.1");

    params.deviceType = "Phone";
    params.osName = "OpenHarmony";
    params.osMajorVersion = -1;
    params.osSeniorVersion = 1;
    params.chromeCompatibleVersion = "144";
    params.arkWebVersion = "5.1.6.1";
    params.appendMobile = true;
    ua = UserAgentBuilder::BuildUserAgentLite(params);
    EXPECT_EQ(ua,
        "Mozilla/5.0 (Phone; OpenHarmony) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/144.0.0.0 Safari/537.36  ArkWeb/5.1.6.1 Mobile");
}

/**
 * @tc.name: NwebUserAgentBuilderTest_BuildUserAgentLite_004
 * @tc.desc: Field combination matrix across device types, chrome versions and mobile flags.
 */
HWTEST_F(NwebUserAgentBuilderTest, NwebUserAgentBuilderTest_BuildUserAgentLite_004, TestSize.Level1)
{
    struct Case {
        std::string deviceType;
        std::string osName;
        int32_t major;
        int32_t senior;
        std::string chrome;
        std::string version;
        bool mobile;
        std::string expected;
    };
    std::vector<Case> cases = {
        { "Phone", "OpenHarmony", 5, 0, "144", "5.0.0.1", true,
          "Mozilla/5.0 (Phone; OpenHarmony 5.0) AppleWebKit/537.36 (KHTML, like Gecko) "
          "Chrome/144.0.0.0 Safari/537.36  ArkWeb/5.0.0.1 Mobile" },
        { "Tablet", "OpenHarmony", 6, 2, "132", "6.2.0.1", false,
          "Mozilla/5.0 (Tablet; OpenHarmony 6.2) AppleWebKit/537.36 (KHTML, like Gecko) "
          "Chrome/132.0.0.0 Safari/537.36  ArkWeb/6.2.0.1" },
        { "PC", "OpenHarmony", 7, 1, "114", "7.1.0.1", true,
          "Mozilla/5.0 (PC; OpenHarmony 7.1) AppleWebKit/537.36 (KHTML, like Gecko) "
          "Chrome/114.0.0.0 Safari/537.36  ArkWeb/7.1.0.1 Mobile" },
        { "Phone", "CustomOS", 6, 0, "144", "6.0.6.1", false,
          "Mozilla/5.0 (Phone; CustomOS 6.0) AppleWebKit/537.36 (KHTML, like Gecko) "
          "Chrome/144.0.0.0 Safari/537.36  ArkWeb/6.0.6.1" },
    };
    for (const auto& item : cases) {
        UserAgentLiteParams params;
        params.deviceType = item.deviceType;
        params.osName = item.osName;
        params.osMajorVersion = item.major;
        params.osSeniorVersion = item.senior;
        params.chromeCompatibleVersion = item.chrome;
        params.arkWebVersion = item.version;
        params.appendMobile = item.mobile;
        std::string ua = UserAgentBuilder::BuildUserAgentLite(params);
        EXPECT_EQ(ua, item.expected);
    }
}

/**
 * @tc.name: NwebUserAgentBuilderTest_BuildDefaultUserAgentLite_001
 * @tc.desc: In the UT environment libarkweb_engine.so is not installed; the default
 *           path degrades to an empty string with a non-OK resolve result and no crash.
 */
HWTEST_F(NwebUserAgentBuilderTest, NwebUserAgentBuilderTest_BuildDefaultUserAgentLite_001, TestSize.Level1)
{
    std::string ua;
    ArkWeb::ArkWebVersionResolveResult result = UserAgentBuilder::BuildDefaultUserAgentLite(ua);
    EXPECT_NE(result, ArkWeb::ArkWebVersionResolveResult::OK);
    EXPECT_TRUE(ua.empty());
    EXPECT_TRUE(UserAgentBuilder::BuildDefaultUserAgentLite().empty());
}

/**
 * @tc.name: NwebUserAgentBuilderTest_NWebHelperGetDefaultUserAgentLite_001
 * @tc.desc: NWebHelper entry works before engine initialization and returns an empty
 *           string when the engine version is unavailable (no crash, no init).
 */
HWTEST_F(NwebUserAgentBuilderTest, NwebUserAgentBuilderTest_NWebHelperGetDefaultUserAgentLite_001, TestSize.Level1)
{
    std::string ua = NWebHelper::Instance().GetDefaultUserAgentLite();
    EXPECT_TRUE(ua.empty());

    // Verify the detailed overload also returns non-OK with empty string.
    std::string ua2;
    ArkWeb::ArkWebVersionResolveResult result = UserAgentBuilder::BuildDefaultUserAgentLite(ua2);
    EXPECT_NE(result, ArkWeb::ArkWebVersionResolveResult::OK);
    EXPECT_TRUE(ua2.empty());

    // NWebHelper and UserAgentBuilder return consistent results.
    EXPECT_EQ(ua, ua2);
}

} // namespace OHOS::NWeb
