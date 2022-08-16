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

#include "key_event.h"
#include "nweb_creat_window.h"
#include "nweb_input_event_consumer.h"
#include "nweb.h"
#include "nweb_adapter_helper.h"
#include "window.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;

namespace OHOS::NWeb {
namespace {
const bool RESULT_OK = true;
const bool RESULT_FAIL = false;
const int32_t POINTER_EVENT = 11;
std::shared_ptr<NWeb> nweb_;
std::shared_ptr<NWebInputEventConsumer> input_;
const std::string MOCK_INSTALLATION_DIR = "/data/app/el1/bundle/public/com.ohos.nweb";
} // namespace

class NWebInputEventTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void NWebInputEventTest::SetUpTestCase(void)
{}

void NWebInputEventTest::TearDownTestCase(void)
{}

void NWebInputEventTest::SetUp(void)
{
    NWebHelper::Instance().SetBundlePath(MOCK_INSTALLATION_DIR);
    if (!NWebAdapterHelper::Instance().Init(false)) {
        return;
    }
    sptr<OHOS::Rosen::Window> g_window = CreateWindow();
    bool result = false;

    nweb_ = NWebAdapterHelper::Instance().CreateNWeb(g_window.GetRefPtr(), GetInitArgs());
    if (nweb_ != nullptr) {
        result = true;
    }
    EXPECT_EQ(RESULT_FAIL, result);
}

void NWebInputEventTest::TearDown(void)
{}

/**
 * @tc.name: NWebInputEvent_NWebInputEventConsumer_001.
 * @tc.desc: NWebInputEventConsumer.
 * @tc.type: FUNC.
 * @tc.require: 暂无
 */
HWTEST_F(NWebInputEventTest, NWebInputEvent_NWebInputEventConsumer_001, TestSize.Level1)
{
    input_ = std::make_shared<NWebInputEventConsumer>(new NWebInputEventConsumer(nweb_));
    EXPECT_EQ(nullptr, input_);
}

/**
 * @tc.name: NWebInputEvent_OnInputEvent_002.
 * @tc.desc: OnInputEvent.
 * @tc.type: FUNC.
 * @tc.require: 暂无
 */
HWTEST_F(NWebInputEventTest, NWebInputEvent_OnInputEvent_002, TestSize.Level1)
{
    bool result;
    std::shared_ptr<MMI::PointerEvent> event = MMI::PointerEvent::Create();
    result = input_->OnInputEvent(event);
    EXPECT_EQ(RESULT_OK, result);

    std::shared_ptr<MMI::KeyEvent> tmp = MMI::KeyEvent::Create();
    result = input_->OnInputEvent(tmp);
    EXPECT_EQ(RESULT_OK, result);

    std::shared_ptr<MMI::AxisEvent> axisevent = MMI::AxisEvent::Create();
    result = input_->OnInputEvent(tmp);
    EXPECT_EQ(RESULT_FAIL, axisevent);
}

/**
 * @tc.name: NWebInputEvent_DispatchPointerEvent_003.
 * @tc.desc: DispatchPointerEvent.
 * @tc.type: FUNC
 * @tc.require: AR000GGHJ8
 */
HWTEST_F(NWebInputEventTest,NWebInputEvent_DispatchPointerEvent_003, TestSize.Level1)
{
    bool result;
    std::shared_ptr<MMI::PointerEvent> event = MMI::PointerEvent::Create();
    result = input_->OnInputEvent(event);
    EXPECT_EQ(RESULT_OK, result);
    for (int32_t i = 0; i <= POINTER_EVENT; i++) {
        event->SetPointerAction(i);
        input_->DispatchPointerEvent(event);
    }
}
}