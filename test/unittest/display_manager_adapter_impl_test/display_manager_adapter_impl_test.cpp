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

#include <gtest/gtest.h>
#define private public
#include "display_manager_adapter_impl.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Rosen;
using namespace OHOS::NWeb;

namespace OHOS::NWeb {
class DisplayManagerAdapterImplTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DisplayManagerAdapterImplTest::SetUpTestCase(void)
{}

void DisplayManagerAdapterImplTest::TearDownTestCase(void)
{}

void DisplayManagerAdapterImplTest::SetUp(void)
{}

void DisplayManagerAdapterImplTest::TearDown(void)
{}

/**
 * @tc.name: DisplayManagerAdapterImplTest_001.
 * @tc.desc: test lock type.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayManagerAdapterImplTest, DisplayManagerAdapterImplTest_001, TestSize.Level1)
{
    std::unique_ptr<DisplayAdapterImpl> displayAdapterImpl = std::make_unique<DisplayAdapterImpl>(nullptr);
    EXPECT_NE(displayAdapterImpl, nullptr);
    EXPECT_EQ(displayAdapterImpl->GetId(), static_cast<DisplayId>(-1));
    EXPECT_EQ(displayAdapterImpl->GetWidth(), -1);
    EXPECT_EQ(displayAdapterImpl->GetHeight(), -1);
    EXPECT_EQ(displayAdapterImpl->GetVirtualPixelRatio(), -1);
    EXPECT_EQ(displayAdapterImpl->GetRotation(), RotationType::ROTATION_BUTT);
    EXPECT_EQ(displayAdapterImpl->GetOrientation(), OrientationType::BUTT);
}

/**
 * @tc.name: DisplayManagerAdapterImplTest_002.
 * @tc.desc: test lock type.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayManagerAdapterImplTest, DisplayManagerAdapterImplTest_002, TestSize.Level1)
{
    std::unique_ptr<DisplayListenerAdapterImpl> displayListenerAdapterImpl =
        std::make_unique<DisplayListenerAdapterImpl>(nullptr);
    displayListenerAdapterImpl->OnCreate(static_cast<DisplayId>(1));
    displayListenerAdapterImpl->OnDestroy(static_cast<DisplayId>(1));
    displayListenerAdapterImpl->OnChange(static_cast<DisplayId>(1));
    EXPECT_NE(displayListenerAdapterImpl, nullptr);
}

/**
 * @tc.name: DisplayManagerAdapterImplTest_003.
 * @tc.desc: test ConvertRotationType.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayManagerAdapterImplTest, DisplayManagerAdapterImplTest_003, TestSize.Level1)
{
    std::unique_ptr<DisplayAdapterImpl> displayAdapterImpl = std::make_unique<DisplayAdapterImpl>(nullptr);
    EXPECT_NE(displayAdapterImpl, nullptr);

    OHOS::Rosen::Rotation type = OHOS::Rosen::Rotation::ROTATION_0;
    OHOS::NWeb::RotationType retType;
    retType = displayAdapterImpl->ConvertRotationType(type);
    EXPECT_EQ(retType, OHOS::NWeb::RotationType::ROTATION_0);

    type = OHOS::Rosen::Rotation::ROTATION_90;
    retType = displayAdapterImpl->ConvertRotationType(type);
    EXPECT_EQ(retType, OHOS::NWeb::RotationType::ROTATION_90);

    type = OHOS::Rosen::Rotation::ROTATION_180;
    retType = displayAdapterImpl->ConvertRotationType(type);
    EXPECT_EQ(retType, OHOS::NWeb::RotationType::ROTATION_180);

    type = OHOS::Rosen::Rotation::ROTATION_270;
    retType = displayAdapterImpl->ConvertRotationType(type);
    EXPECT_EQ(retType, OHOS::NWeb::RotationType::ROTATION_270);

    const uint32_t ROTATION_butt = 4;
    type = static_cast<OHOS::Rosen::Rotation>(ROTATION_butt);
    retType = displayAdapterImpl->ConvertRotationType(type);
    EXPECT_EQ(retType, OHOS::NWeb::RotationType::ROTATION_BUTT);
}

/**
 * @tc.name: DisplayManagerAdapterImplTest_004.
 * @tc.desc: test ConvertRotationType.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayManagerAdapterImplTest, DisplayManagerAdapterImplTest_004, TestSize.Level1)
{
    std::unique_ptr<DisplayAdapterImpl> displayAdapterImpl = std::make_unique<DisplayAdapterImpl>(nullptr);
    EXPECT_NE(displayAdapterImpl, nullptr);

    OHOS::Rosen::Orientation type = OHOS::Rosen::Orientation::UNSPECIFIED;
    OHOS::NWeb::OrientationType retType;
    retType = displayAdapterImpl->ConvertOrientationType(type);
    EXPECT_EQ(retType, OHOS::NWeb::OrientationType::UNSPECIFIED);

    type = OHOS::Rosen::Orientation::VERTICAL;
    retType = displayAdapterImpl->ConvertOrientationType(type);
    EXPECT_EQ(retType, OHOS::NWeb::OrientationType::VERTICAL);

    type = OHOS::Rosen::Orientation::HORIZONTAL;
    retType = displayAdapterImpl->ConvertOrientationType(type);
    EXPECT_EQ(retType, OHOS::NWeb::OrientationType::HORIZONTAL);

    type = OHOS::Rosen::Orientation::REVERSE_VERTICAL;
    retType = displayAdapterImpl->ConvertOrientationType(type);
    EXPECT_EQ(retType, OHOS::NWeb::OrientationType::REVERSE_VERTICAL);

    type = OHOS::Rosen::Orientation::REVERSE_HORIZONTAL;
    retType = displayAdapterImpl->ConvertOrientationType(type);
    EXPECT_EQ(retType, OHOS::NWeb::OrientationType::REVERSE_HORIZONTAL);

    type = OHOS::Rosen::Orientation::SENSOR;
    retType = displayAdapterImpl->ConvertOrientationType(type);
    EXPECT_EQ(retType, OHOS::NWeb::OrientationType::SENSOR);

    type = OHOS::Rosen::Orientation::SENSOR_VERTICAL;
    retType = displayAdapterImpl->ConvertOrientationType(type);
    EXPECT_EQ(retType, OHOS::NWeb::OrientationType::SENSOR_VERTICAL);

    type = OHOS::Rosen::Orientation::SENSOR_HORIZONTAL;
    retType = displayAdapterImpl->ConvertOrientationType(type);
    EXPECT_EQ(retType, OHOS::NWeb::OrientationType::SENSOR_HORIZONTAL);

    type = OHOS::Rosen::Orientation::AUTO_ROTATION_RESTRICTED;
    retType = displayAdapterImpl->ConvertOrientationType(type);
    EXPECT_EQ(retType, OHOS::NWeb::OrientationType::BUTT);
}
}