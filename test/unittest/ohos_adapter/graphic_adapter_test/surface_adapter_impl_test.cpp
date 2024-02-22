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

#include "gtest/gtest.h"
#include "nweb_log.h"
#define private public
#include "surface_adapter_impl.h"
#undef private
#include "ohos_adapter_helper.h"

using testing::ext::TestSize;

namespace OHOS::NWeb {
class BufferConsumerListenerTest : public IBufferConsumerListenerAdapter {
public:
    BufferConsumerListenerTest() = default;
    ~BufferConsumerListenerTest() override = default;
    void OnBufferAvailable(std::shared_ptr<SurfaceBufferAdapter> buffer) override
    {
        WVLOG_I("test buffer is available, the format=%{public}d", buffer->GetFormat());
    }
};

class SurfaceAdapterImplTest : public testing::Test {
protected:
    void SetUp() override;
    BufferRequestConfig GetBufferRequestConfig(int32_t myFormat);
    std::unique_ptr<ConsumerSurfaceAdapterImpl> surfaceAdapter_;
    std::unique_ptr<IBufferConsumerListenerAdapter> listenerTest_;
    static inline BufferFlushConfig flushConfig_ = {
        .damage = {
            .w = 0x100,
            .h = 0x100,
        },
    };
};

void SurfaceAdapterImplTest::SetUp()
{
    surfaceAdapter_ = std::make_unique<ConsumerSurfaceAdapterImpl>();
    ASSERT_NE(surfaceAdapter_, nullptr);
    ASSERT_NE(surfaceAdapter_->cSurface_, nullptr);
    listenerTest_ = std::make_unique<BufferConsumerListenerTest>();
    EXPECT_NE(listenerTest_, nullptr);
}

BufferRequestConfig SurfaceAdapterImplTest::GetBufferRequestConfig(int32_t myFormat)
{
    BufferRequestConfig requestConfig = {
        .width = 0x100,
        .height = 0x100,
        .strideAlignment = 0x8,
        .format = myFormat,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA,
        .timeout = 0,
    };
    return requestConfig;
}

/**
 * @tc.name: InvalidSceneOfSurfaceAdapterImpl.
 * @tc.desc: test invalid scene of SurfaceAdapterImpl.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(SurfaceAdapterImplTest, InvalidSceneOfSurfaceAdapterImpl, TestSize.Level1)
{
    EXPECT_EQ(surfaceAdapter_->RegisterConsumerListener(nullptr), -1);
    EXPECT_EQ(surfaceAdapter_->ReleaseBuffer(nullptr, 0), -1);

    surfaceAdapter_->cSurface_ = nullptr;
    EXPECT_EQ(surfaceAdapter_->RegisterConsumerListener(std::move(listenerTest_)), -1);
    EXPECT_EQ(surfaceAdapter_->ReleaseBuffer(nullptr, 0), -1);
    EXPECT_EQ(surfaceAdapter_->SetUserData("testkey", "testval"), -1);
    EXPECT_EQ(surfaceAdapter_->SetQueueSize(0), -1);
}

/**
 * @tc.name: InvalidSceneOfBufferConsumerListenerImpl.
 * @tc.desc: test invalid scene of BufferConsumerListenerImpl.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(SurfaceAdapterImplTest, InvalidSceneOfBufferConsumerListenerImpl, TestSize.Level1)
{
    auto consumerListener =
        std::make_unique<BufferConsumerListenerImpl>(surfaceAdapter_->cSurface_, std::move(listenerTest_));
    ASSERT_NE(consumerListener, nullptr);
    consumerListener->OnBufferAvailable();
    consumerListener->listener_ = nullptr;
    consumerListener->OnBufferAvailable();
    consumerListener->cSurface_ = nullptr;
    consumerListener->OnBufferAvailable();
}

/**
 * @tc.name: InvalidSceneOfSurfaceBufferAdapterImpl.
 * @tc.desc: test invalid scene of SurfaceBufferAdapterImpl.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(SurfaceAdapterImplTest, InvalidSceneOfSurfaceBufferAdapterImpl, TestSize.Level1)
{
    auto bufferAdapter = std::make_unique<SurfaceBufferAdapterImpl>(nullptr);
    ASSERT_NE(bufferAdapter, nullptr);
    EXPECT_EQ(bufferAdapter->GetFileDescriptor(), -1);
    EXPECT_EQ(bufferAdapter->GetWidth(), -1);
    EXPECT_EQ(bufferAdapter->GetHeight(), -1);
    EXPECT_EQ(bufferAdapter->GetStride(), -1);
    EXPECT_EQ(bufferAdapter->GetFormat(), -1);
    EXPECT_EQ(bufferAdapter->GetSize(), 0);
    EXPECT_EQ(bufferAdapter->GetVirAddr(), nullptr);
}

/**
 * @tc.name: HandlesNormalScene.
 * @tc.desc: test normal scene of SurfaceAdapterImpl.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(SurfaceAdapterImplTest, HandlesNormalScene, TestSize.Level1)
{
    EXPECT_EQ(surfaceAdapter_->RegisterConsumerListener(std::move(listenerTest_)), OHOS::GSERROR_OK);
    EXPECT_EQ(surfaceAdapter_->SetUserData("testkey", "testval"), OHOS::GSERROR_OK);
    EXPECT_EQ(surfaceAdapter_->SetQueueSize(1), OHOS::GSERROR_OK);
    auto cSurface = surfaceAdapter_->GetConsumerSurface();
    auto producer = cSurface->GetProducer();
    sptr<Surface> pSurface = Surface::CreateSurfaceAsProducer(producer);
    ASSERT_NE(pSurface, nullptr);

    int32_t fence = -1;
    std::array formatArray = { GRAPHIC_PIXEL_FMT_RGBA_8888, GRAPHIC_PIXEL_FMT_YCBCR_420_SP };
    for (auto format : formatArray) {
        sptr<SurfaceBuffer> buffer;
        auto requestConfig = GetBufferRequestConfig(format);
        EXPECT_EQ(pSurface->RequestBuffer(buffer, fence, requestConfig), OHOS::GSERROR_OK);
        ASSERT_NE(buffer, nullptr);
        EXPECT_EQ(pSurface->FlushBuffer(buffer, fence, flushConfig_), OHOS::GSERROR_OK);

        auto bufferAdapter = std::make_unique<SurfaceBufferAdapterImpl>(buffer);
        ASSERT_NE(bufferAdapter, nullptr);
        EXPECT_GE(bufferAdapter->GetFileDescriptor(), 0);
        EXPECT_GE(bufferAdapter->GetWidth(), 0);
        EXPECT_GE(bufferAdapter->GetHeight(), 0);
        EXPECT_GE(bufferAdapter->GetStride(), 0);
        EXPECT_GE(bufferAdapter->GetFormat(), 0);
        EXPECT_GT(bufferAdapter->GetSize(), 0);
        EXPECT_NE(bufferAdapter->GetVirAddr(), nullptr);

        surfaceAdapter_->ReleaseBuffer(std::move(bufferAdapter), fence);
    }
}

/**
 * @tc.name: HandlesNormalScene.
 * @tc.desc: test normal scene of PixelFormatAdapter.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST(PixelFormatAdapterTest, HandlesNormalScene, TestSize.Level1)
{
    EXPECT_NE(PixelFormatAdapter::PIXEL_FMT_RGBA_8888, 0);
    EXPECT_NE(PixelFormatAdapter::PIXEL_FMT_YCBCR_420_SP, 0);
    EXPECT_EQ((int)PixelFormatAdapter::PIXEL_FMT_RGBA_8888, (int)GRAPHIC_PIXEL_FMT_RGBA_8888);
    EXPECT_EQ((int)PixelFormatAdapter::PIXEL_FMT_YCBCR_420_SP, (int)GRAPHIC_PIXEL_FMT_YCBCR_420_SP);
}
} // namespace OHOS::NWeb
