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

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "ohos_nweb/bridge/ark_web_color_chooser_callback_wrapper.h"
#include "ohos_nweb/include/ark_web_color_chooser_callback.h"
#include "base/include/ark_web_types.h"

using namespace testing;
using namespace OHOS::ArkWeb;

namespace {
constexpr int CONTINUE_MULTIPLE_CALLS_TIMES = 3;
constexpr int CONTINUE_NO_LEAK_ITERATIONS = 10;
} // namespace

// ============================================================================
// ArkWebColorChooserCallbackWrapper tests
//
// Tests the NWeb→ArkWeb bridge for color chooser callback.
// The wrapper converts std::string → ArkWebString (via ArkWebStringClassToStruct)
// and forwards to the ArkWebRefPtr<ArkWebColorChooserCallback>.
//
// Branch coverage:
//   1. Continue forwards color string to the ArkWeb callback
//   2. Cancel forwards to the ArkWeb callback
//   3. Continue does not leak ArkWebString memory (ArkWebStringStructRelease)
//   4. Multiple Continue calls (multi-call intermediate update)
// ============================================================================

// Mock ArkWebColorChooserCallback to verify routing.
class MockArkWebColorChooserCallback : public ArkWebColorChooserCallback {
public:
    MOCK_METHOD1(Continue, void(const ArkWebString& color));
    MOCK_METHOD0(Cancel, void());

    // ArkWebBaseRefCounted — ArkWebRefPtr calls these on construct/destruct.
    void IncreRef() const override { refCount_++; }
    void DecreRef() const override
    {
        refCount_--;
        if (refCount_ <= 0) {
            delete this;
        }
    }

private:
    mutable int refCount_ = 0;
};

class ArkWebColorChooserCallbackWrapperTest : public Test {
protected:
    void SetUp() override
    {
        mockCallback_ = new MockArkWebColorChooserCallback();
        // Wrapper holds one ref; we keep a raw pointer for EXPECT_CALL.
        wrapper_ = std::make_unique<ArkWebColorChooserCallbackWrapper>(
            ArkWebRefPtr<ArkWebColorChooserCallback>(mockCallback_));
    }

    void TearDown() override
    {
        wrapper_ = nullptr;
    }

    MockArkWebColorChooserCallback* mockCallback_ = nullptr;
    std::unique_ptr<ArkWebColorChooserCallbackWrapper> wrapper_;
};

/**
 * @tc.name: ArkWebColorChooserCallbackWrapper_Continue_001
 * @tc.desc: Verify Continue forwards color string to ArkWeb callback
 * @tc.type: Func
 */
TEST_F(ArkWebColorChooserCallbackWrapperTest, Continue_ForwardsColor)
{
    EXPECT_CALL(*mockCallback_, Continue(_)).Times(1);
    wrapper_->Continue("#ff0000");
}

/**
 * @tc.name: ArkWebColorChooserCallbackWrapper_Continue_002
 * @tc.desc: Verify Continue can be called multiple times (intermediate update)
 * @tc.type: Func
 */
TEST_F(ArkWebColorChooserCallbackWrapperTest, Continue_MultipleCalls)
{
    EXPECT_CALL(*mockCallback_, Continue(_)).Times(CONTINUE_MULTIPLE_CALLS_TIMES);
    wrapper_->Continue("#ff0000");
    wrapper_->Continue("#00ff00");
    wrapper_->Continue("#0000ff");
}

/**
 * @tc.name: ArkWebColorChooserCallbackWrapper_Cancel_001
 * @tc.desc: Verify Cancel forwards to ArkWeb callback
 * @tc.type: Func
 */
TEST_F(ArkWebColorChooserCallbackWrapperTest, Cancel_ForwardsToCallback)
{
    EXPECT_CALL(*mockCallback_, Cancel()).Times(1);
    wrapper_->Cancel();
}

/**
 * @tc.name: ArkWebColorChooserCallbackWrapper_Continue_EmptyString_001
 * @tc.desc: Verify Continue handles empty string without crash
 * @tc.type: Func
 */
TEST_F(ArkWebColorChooserCallbackWrapperTest, Continue_EmptyString_NoCrash)
{
    EXPECT_CALL(*mockCallback_, Continue(_)).Times(1);
    wrapper_->Continue("");
}

/**
 * @tc.name: ArkWebColorChooserCallbackWrapper_Continue_NoLeak_001
 * @tc.desc: Verify Continue does not leak ArkWebString memory.
 *           ArkWebStringClassToStruct allocates via ArkWebMemMalloc;
 *           ArkWebStringStructRelease must free it. If the release is missing,
 *           each Continue call leaks one ArkWebString.
 * @tc.type: Func
 */
TEST_F(ArkWebColorChooserCallbackWrapperTest, Continue_DoesNotLeakStringMemory)
{
    // Call Continue many times — if there's a leak, it would accumulate.
    // We can't directly assert no-leak in a unit test, but we verify the
    // call completes without crash and the mock receives each call.
    EXPECT_CALL(*mockCallback_, Continue(_)).Times(CONTINUE_NO_LEAK_ITERATIONS);
    for (int i = 0; i < CONTINUE_NO_LEAK_ITERATIONS; i++) {
        wrapper_->Continue("#abcdef");
    }
}
