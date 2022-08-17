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
#include <securec.h>
#include <ui/rs_surface_node.h>
#include <unordered_map>

#include "nweb.h"
#include "nweb_adapter_helper.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;

namespace OHOS::NWeb {
namespace {

} // namespace

class NWebAafwkAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void NWebAafwkAdapterTest::SetUpTestCase(void)
{
    
}

void NWebAafwkAdapterTest::TearDownTestCase(void)
{}

void NWebAafwkAdapterTest::SetUp(void)
{}

void NWebAafwkAdapterTest::TearDown(void)
{}

/**
 * @tc.name: NWebInputEvent_NWebInputEventConsumer_001.
 * @tc.desc: NWebInputEventConsumer.
 * @tc.type: FUNC.
 * @tc.require: 暂无
 */
HWTEST_F(NWebAafwkAdapterTest, NWebInputEvent_NWebInputEventConsumer_001, TestSize.Level1)
{
    
   //EXPECT_EQ(RESULT_OK, result);
}

/**
 * @tc.name: NWebInputEvent_OnInputEvent_002.
 * @tc.desc: OnInputEvent.
 * @tc.type: FUNC.
 * @tc.require: 暂无
 */
HWTEST_F(NWebAafwkAdapterTest, NWebInputEvent_OnInputEvent_002, TestSize.Level1)
{
    
    //EXPECT_EQ(RESULT_FAIL, result);
}
}