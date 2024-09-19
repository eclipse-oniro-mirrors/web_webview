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

#define private public
#include "iconsumer_surface.h"
#include "native_image_adapter_impl.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::NWeb {
class NativeImageAdapterImplTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void NativeImageAdapterImplTest::SetUpTestCase(void) {}

void NativeImageAdapterImplTest::TearDownTestCase(void) {}

void NativeImageAdapterImplTest::SetUp(void) {}

void NativeImageAdapterImplTest::TearDown(void) {}

/**
 * @tc.name: NativeImageAdapterImplTest_UpdateSurfaceImage_001
 * @tc.desc: UpdateSurfaceImage.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NativeImageAdapterImplTest, NativeImageAdapterImplTest_UpdateSurfaceImage_001, TestSize.Level1)
{
    std::shared_ptr<NativeImageAdapterImpl> imagerAdapter = std::make_shared<NativeImageAdapterImpl>();
    EXPECT_NE(imagerAdapter, nullptr);
    int32_t result = imagerAdapter->UpdateSurfaceImage();
    EXPECT_EQ(result, SURFACE_ERROR_ERROR);
    NWebNativeWindow window = imagerAdapter->AquireNativeWindowFromNativeImage();
    EXPECT_EQ(window, nullptr);
    int32_t context = imagerAdapter->AttachContext(1);
    EXPECT_EQ(context, SURFACE_ERROR_ERROR);
    context = imagerAdapter->DetachContext();
    EXPECT_EQ(context, SURFACE_ERROR_ERROR);
    uint32_t textureId = 1;
    uint32_t textureTarget = 1;
    imagerAdapter->CreateNativeImage(textureId, textureTarget);
    result = imagerAdapter->UpdateSurfaceImage();
    EXPECT_EQ(result, 0);
    window = imagerAdapter->AquireNativeWindowFromNativeImage();
    EXPECT_NE(window, nullptr);
    imagerAdapter->AttachContext(1);
    imagerAdapter->DetachContext();
}

/**
 * @tc.name: NativeImageAdapterImplTest_GetTimestamp_001
 * @tc.desc: GetTimestamp.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NativeImageAdapterImplTest, NativeImageAdapterImplTest_GetTimestamp_001, TestSize.Level1)
{
    std::shared_ptr<NativeImageAdapterImpl> imagerAdapter = std::make_shared<NativeImageAdapterImpl>();
    EXPECT_NE(imagerAdapter, nullptr);
    int32_t result = imagerAdapter->GetTimestamp();
    EXPECT_EQ(result, SURFACE_ERROR_ERROR);
    uint32_t textureId = 1;
    uint32_t textureTarget = 1;
    imagerAdapter->CreateNativeImage(textureId, textureTarget);
    result = imagerAdapter->GetTimestamp();
    EXPECT_EQ(result, 0);
}

/**
 * @tc.name: NativeImageAdapterImplTest_GetTransformMatrix_001
 * @tc.desc: GetTransformMatrix.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NativeImageAdapterImplTest, NativeImageAdapterImplTest_GetTransformMatrix_001, TestSize.Level1)
{
    std::shared_ptr<NativeImageAdapterImpl> imagerAdapter = std::make_shared<NativeImageAdapterImpl>();
    EXPECT_NE(imagerAdapter, nullptr);
    float matrix[16] = { 0 };
    int32_t result = imagerAdapter->GetTransformMatrix(matrix);
    EXPECT_EQ(result, SURFACE_ERROR_ERROR);
    uint32_t textureId = 1;
    uint32_t textureTarget = 1;
    imagerAdapter->CreateNativeImage(textureId, textureTarget);
    result = imagerAdapter->GetTransformMatrix(matrix);
    EXPECT_EQ(result, 0);
}

/**
 * @tc.name: NativeImageAdapterImplTest_GetSurfaceId001
 * @tc.desc:GetSurfaceId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NativeImageAdapterImplTest, NativeImageAdapterImplTest_GetSurfaceId_001, TestSize.Level1)
{
    std::shared_ptr<NativeImageAdapterImpl> imagerAdapter = std::make_shared<NativeImageAdapterImpl>();
    EXPECT_NE(imagerAdapter, nullptr);
    uint64_t surfaceId = 1;
    int32_t result = imagerAdapter->GetSurfaceId(&surfaceId);
    EXPECT_EQ(result, SURFACE_ERROR_ERROR);
    uint32_t textureId = 1;
    uint32_t textureTarget = 1;
    imagerAdapter->CreateNativeImage(textureId, textureTarget);
    result = imagerAdapter->GetSurfaceId(&surfaceId);
    EXPECT_EQ(result, 0);
}

/**
 * @tc.name: NativeImageAdapterImplTest_SetOnFrameAvailableListener001
 * @tc.desc:SetOnFrameAvailableListener.
 * @tc.type: FUNC
 * @tc.require:s
 */
HWTEST_F(NativeImageAdapterImplTest, NativeImageAdapterImplTest_SetOnFrameAvailableListener_001, TestSize.Level1)
{
    std::shared_ptr<NativeImageAdapterImpl> imagerAdapter = std::make_shared<NativeImageAdapterImpl>();
    EXPECT_NE(imagerAdapter, nullptr);
    int32_t result = imagerAdapter->SetOnFrameAvailableListener(nullptr);
    EXPECT_EQ(result, SURFACE_ERROR_ERROR);
    uint32_t textureId = 1;
    uint32_t textureTarget = 1;
    imagerAdapter->CreateNativeImage(textureId, textureTarget);
    result = imagerAdapter->SetOnFrameAvailableListener(nullptr);
    EXPECT_EQ(result, SURFACE_ERROR_ERROR);
}

/**
 * @tc.name: NativeImageAdapterImplTest_UnsetOnFrameAvailableListener001
 * @tc.desc:UnsetOnFrameAvailableListener.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NativeImageAdapterImplTest, NativeImageAdapterImplTest_UnsetOnFrameAvailableListener_001, TestSize.Level1)
{
    std::shared_ptr<NativeImageAdapterImpl> imagerAdapter = std::make_shared<NativeImageAdapterImpl>();
    EXPECT_NE(imagerAdapter, nullptr);
    int32_t result = imagerAdapter->UnsetOnFrameAvailableListener();
    EXPECT_EQ(result, SURFACE_ERROR_ERROR);
    uint32_t textureId = 1;
    uint32_t textureTarget = 1;
    imagerAdapter->CreateNativeImage(textureId, textureTarget);
    result = imagerAdapter->UnsetOnFrameAvailableListener();
    EXPECT_EQ(result, 0);
}

/**
 * @tc.name: NativeImageAdapterImplTest_DestroyNativeImage001
 * @tc.desc:DestroyNativeImage.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NativeImageAdapterImplTest, NativeImageAdapterImplTest_DestroyNativeImage_001, TestSize.Level1)
{
    std::shared_ptr<NativeImageAdapterImpl> imagerAdapter = std::make_shared<NativeImageAdapterImpl>();
    EXPECT_NE(imagerAdapter, nullptr);
    imagerAdapter->DestroyNativeImage();
}

/**
 * @tc.name: NativeImageAdapterImplTest_OhosImageReader_newNativeImage001
 * @tc.desc:OhosImageReader_newNativeImage.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NativeImageAdapterImplTest, NativeImageAdapterImplTest_OhosImageReader_newNativeImage_001, TestSize.Level1)
{
    std::shared_ptr<NativeImageAdapterImpl> imagerAdapter = std::make_shared<NativeImageAdapterImpl>();
    EXPECT_NE(imagerAdapter, nullptr);
    imagerAdapter->OhosImageReader_newNativeImage();
    EXPECT_NE(imagerAdapter->ohNativeImage_, nullptr);
}

/**
 * @tc.name: NativeImageAdapterImplTest_OhosImageReader_acquireNativeWindowBuffer001
 * @tc.desc:OhosImageReader_acquireNativeWindowBuffer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NativeImageAdapterImplTest, NativeImageAdapterImplTest_OhosImageReader_acquireNativeWindowBuffer_001, TestSize.Level1)
{
    std::shared_ptr<NativeImageAdapterImpl> imagerAdapter = std::make_shared<NativeImageAdapterImpl>();
    EXPECT_NE(imagerAdapter, nullptr);

    void* windowBuffer = nullptr;
    int fenceId = -1;
    int32_t ret = imagerAdapter->OhosImageReader_acquireNativeWindowBuffer(&windowBuffer, &fenceId);
    EXPECT_EQ(ret, SURFACE_ERROR_ERROR);

    imagerAdapter->OhosImageReader_newNativeImage();
    EXPECT_NE(imagerAdapter->ohNativeImage_, nullptr);
    ret = imagerAdapter->OhosImageReader_acquireNativeWindowBuffer(&windowBuffer, &fenceId);
    EXPECT_EQ(ret, GSERROR_INTERNAL);
}

/**
 * @tc.name: NativeImageAdapterImplTest_OhosImage_getNativeBuffer001
 * @tc.desc:OhosImage_getNativeBuffer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NativeImageAdapterImplTest, NativeImageAdapterImplTest_OhosImage_getNativeBuffer_001, TestSize.Level1)
{
    std::shared_ptr<NativeImageAdapterImpl> imagerAdapter = std::make_shared<NativeImageAdapterImpl>();
    EXPECT_NE(imagerAdapter, nullptr);

    void* windowBuffer = nullptr;
    void* nativeBuffer = nullptr;
    imagerAdapter->OhosImage_getNativeBuffer(windowBuffer, &nativeBuffer);
}

/**
 * @tc.name: NativeImageAdapterImplTest_OhosImage_delete001
 * @tc.desc:OhosImage_delete.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NativeImageAdapterImplTest, NativeImageAdapterImplTest_OhosImage_delete_001, TestSize.Level1)
{
    std::shared_ptr<NativeImageAdapterImpl> imagerAdapter = std::make_shared<NativeImageAdapterImpl>();
    EXPECT_NE(imagerAdapter, nullptr);

    void* windowBuffer = nullptr;
    int fenceId = -1;
    int32_t ret = imagerAdapter->OhosImage_delete(windowBuffer, fenceId);
    EXPECT_EQ(ret, SURFACE_ERROR_ERROR);

    imagerAdapter->OhosImageReader_newNativeImage();
    EXPECT_NE(imagerAdapter->ohNativeImage_, nullptr);
    imagerAdapter->OhosImage_delete(windowBuffer, fenceId);
}
} // namespace OHOS::NWeb
