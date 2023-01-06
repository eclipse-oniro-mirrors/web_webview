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

#define private public
#include "vsync_adapter_impl.h"
#undef private

using namespace testing;
using namespace testing::ext;

namespace OHOS::NWeb {
class GraphicAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void GraphicAdapterTest::SetUpTestCase(void)
{}

void GraphicAdapterTest::TearDownTestCase(void)
{}

void GraphicAdapterTest::SetUp(void)
{}

void GraphicAdapterTest::TearDown(void)
{}

/**
 * @tc.name: GraphicAdapterTest_RequestVsync_001
 * @tc.desc: RequestVsync.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GraphicAdapterTest, GraphicAdapterTest_RequestVsync_001, TestSize.Level1)
{
    VSyncAdapterImpl adapter;
    void* data = nullptr;
    std::function<void(int64_t, void*)> onKeyEventId = [] (int64_t, void*) {};
    VSyncErrorCode result = adapter.RequestVsync(data, std::move(onKeyEventId));
    EXPECT_EQ(result, VSyncErrorCode::SUCCESS);
    result = adapter.RequestVsync(data, std::move(onKeyEventId));
    EXPECT_EQ(result, VSyncErrorCode::SUCCESS);
}
} // namespace NWeb