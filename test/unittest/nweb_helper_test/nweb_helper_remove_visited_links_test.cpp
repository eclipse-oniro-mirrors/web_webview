/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "nweb_helper.h"
#include "nweb_remove_visited_links_callback.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace NWeb {

class NWebRemoveVisitedLinksCallbackTestImpl : public NWebRemoveVisitedLinksCallback {
public:
    NWebRemoveVisitedLinksCallbackTestImpl() = default;
    ~NWebRemoveVisitedLinksCallbackTestImpl() override = default;

    void OnRemoveComplete() override
    {
        completed_ = true;
    }

    bool IsCompleted() const
    {
        return completed_;
    }

private:
    bool completed_ = false;
};

class NWebHelperRemoveVisitedLinksTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: NWebHelperRemoveVisitedLinksTest_Callback_001
 * @tc.desc: RemoveVisitedLinksSince with valid callback should invoke OnRemoveComplete.
 * @tc.type: FUNC
 */
HWTEST_F(NWebHelperRemoveVisitedLinksTest, NWebHelperRemoveVisitedLinksTest_Callback_001, TestSize.Level1)
{
    auto callback = std::make_shared<NWebRemoveVisitedLinksCallbackTestImpl>();
    ASSERT_NE(callback, nullptr);
    NWebHelper::Instance().RemoveVisitedLinksSince(0, callback);
    EXPECT_TRUE(callback->IsCompleted());
}

/**
 * @tc.name: NWebHelperRemoveVisitedLinksTest_NullCallback_002
 * @tc.desc: RemoveVisitedLinksSince with null callback should not crash.
 * @tc.type: FUNC
 */
HWTEST_F(NWebHelperRemoveVisitedLinksTest, NWebHelperRemoveVisitedLinksTest_NullCallback_002, TestSize.Level1)
{
    NWebHelper::Instance().RemoveVisitedLinksSince(0, nullptr);
    SUCCEED();
}

/**
 * @tc.name: NWebHelperRemoveVisitedLinksTest_ValidTimeMs_003
 * @tc.desc: RemoveVisitedLinksSince with valid timestamp should invoke callback.
 * @tc.type: FUNC
 */
HWTEST_F(NWebHelperRemoveVisitedLinksTest, NWebHelperRemoveVisitedLinksTest_ValidTimeMs_003, TestSize.Level1)
{
    auto callback = std::make_shared<NWebRemoveVisitedLinksCallbackTestImpl>();
    ASSERT_NE(callback, nullptr);
    int64_t timeMs = 1000;
    NWebHelper::Instance().RemoveVisitedLinksSince(timeMs, callback);
    EXPECT_TRUE(callback->IsCompleted());
}

} // namespace NWeb
} // namespace OHOS
