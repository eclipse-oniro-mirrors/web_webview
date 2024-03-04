/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#define private public
#include "avcodec_list.h"
#include "avcodec_video_encoder_impl.h"
#include "media_codec_encoder_adapter_impl.h"
#include "media_codec_list_adapter_impl.h"
#undef private
#include "avsharedmemory.h"
#include "avsharedmemorybase.h"

using testing::ext::TestSize;
using namespace OHOS::MediaAVCodec;

namespace OHOS::NWeb {
class EncoderCallbackImplTest : public testing::Test {};

class EncoderCallbackAdapterMock : public CodecCallbackAdapter {
public:
    EncoderCallbackAdapterMock() = default;

    ~EncoderCallbackAdapterMock() override = default;

    void OnError(ErrorType errorType, int32_t errorCode) override {}

    void OnStreamChanged(const CodecFormatAdapter& formatApadter_) override {}

    void OnNeedInputData(uint32_t index, OhosBuffer buffer) override {}

    void OnNeedOutputData(uint32_t index, BufferInfo info, BufferFlag flag, OhosBuffer buffer) override {}
};

class ProducerSurfaceAdapterMock : public ProducerSurfaceAdapter {
public:
    ProducerSurfaceAdapterMock() = default;

    virtual ~ProducerSurfaceAdapterMock() = default;

    std::shared_ptr<SurfaceBufferAdapter> RequestBuffer(
        int32_t& fence, BufferRequestConfigAdapter& configAdapter) override
    {
        return nullptr;
    };

    int32_t FlushBuffer(std::shared_ptr<SurfaceBufferAdapter> bufferAdapter, int32_t fence,
        BufferFlushConfigAdapter& flushConfigAdapter) override
    {
        return 0;
    };
};

/**
 * @tc.name: EncoderCallbackImpl_NormalTest_001.
 * @tc.desc: test of EncoderCallbackImpl::OnError() OnOutputFormatChanged() OnInputBufferAvailable()
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(EncoderCallbackImplTest, EncoderCallbackImpl_NormalTest_001, TestSize.Level1)
{
    std::shared_ptr<CodecCallbackAdapter> cb = nullptr;
    std::shared_ptr<EncoderCallbackImpl> callbackImpl = std::make_shared<EncoderCallbackImpl>(cb);
    const int32_t errorcode = 0;
    const AVCodecErrorType errorType = AVCODEC_ERROR_EXTEND_START;
    callbackImpl->OnError(errorType, errorcode);
    Media::Format fomat;
    callbackImpl->OnOutputFormatChanged(fomat);
    uint32_t index = 1;
    std::shared_ptr<Media::AVSharedMemory> buffer = nullptr;
    callbackImpl->OnInputBufferAvailable(index, buffer);
    AVCodecBufferInfo info;
    callbackImpl->OnOutputBufferAvailable(1, info, AVCodecBufferFlag::AVCODEC_BUFFER_FLAG_EOS, nullptr);
}

class MediaCodecEncoderAdapterImplTest : public testing::Test {
protected:
    void SetUp() override;
    CodecFormatAdapter formatApadter_ = { 640, 360 };
    CodecConfigPara config_ = { 640, 360, 300000, 15 };
    std::shared_ptr<MediaCodecEncoderAdapterImpl> mediaCodecEncoderAdapterImpl = nullptr;
};

void MediaCodecEncoderAdapterImplTest::SetUp()
{
    EXPECT_EQ(mediaCodecEncoderAdapterImpl, nullptr);
    mediaCodecEncoderAdapterImpl = std::make_unique<MediaCodecEncoderAdapterImpl>();
    EXPECT_NE(mediaCodecEncoderAdapterImpl, nullptr);
    EXPECT_EQ(mediaCodecEncoderAdapterImpl->encoder_, nullptr);
}

/**
 * @tc.name: MediaCodecEncoderAdapterImpl_CreateVideoEncoderByName_001.
 * @tc.desc: test of MediaCodecEncoderAdapterImpl::CreateVideoEncoderByName() CreateVideoEncoderByName()
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(MediaCodecEncoderAdapterImplTest, MediaCodecEncoderAdapterImpl_CreateVideoEncoderByName_001, TestSize.Level1)
{
    const std::string mimetype_ = "testmimeType";
    EXPECT_EQ(mediaCodecEncoderAdapterImpl->CreateVideoCodecByMime(mimetype_), CodecCodeAdapter::ERROR);
    const std::string name_ = "testname";
    EXPECT_EQ(mediaCodecEncoderAdapterImpl->CreateVideoCodecByName(name_), CodecCodeAdapter::ERROR);
}

/**
 * @tc.name: MediaCodecEncoderAdapterImpl_InvalidValueTest_002.
 * @tc.desc: test of InvalidValueScene in MediaCodecEncoderAdapterImpl
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(MediaCodecEncoderAdapterImplTest, MediaCodecEncoderAdapterImpl_InvalidValueTest_002, TestSize.Level1)
{
    uint32_t index = 0;
    EXPECT_EQ(mediaCodecEncoderAdapterImpl->Configure(config_), CodecCodeAdapter::ERROR);
    EXPECT_EQ(mediaCodecEncoderAdapterImpl->Prepare(), CodecCodeAdapter::ERROR);
    EXPECT_EQ(mediaCodecEncoderAdapterImpl->Start(), CodecCodeAdapter::ERROR);
    EXPECT_EQ(mediaCodecEncoderAdapterImpl->Stop(), CodecCodeAdapter::ERROR);
    EXPECT_EQ(mediaCodecEncoderAdapterImpl->Reset(), CodecCodeAdapter::ERROR);
    EXPECT_EQ(mediaCodecEncoderAdapterImpl->Release(), CodecCodeAdapter::ERROR);
    EXPECT_EQ(mediaCodecEncoderAdapterImpl->ReleaseOutputBuffer(index, true), CodecCodeAdapter::ERROR);
    EXPECT_EQ(mediaCodecEncoderAdapterImpl->RequestKeyFrameSoon(), CodecCodeAdapter::ERROR);
    std::shared_ptr<CodecCallbackAdapter> callback = std::make_shared<EncoderCallbackAdapterMock>();
    EXPECT_EQ(mediaCodecEncoderAdapterImpl->SetCodecCallback(callback), CodecCodeAdapter::ERROR);
    std::shared_ptr<ProducerSurfaceAdapter> surface = mediaCodecEncoderAdapterImpl->CreateInputSurface();
    EXPECT_EQ(surface, nullptr);
}

/**
 * @tc.name: MediaCodecEncoderAdapterImpl_NormalTest_003.
 * @tc.desc: test of NormalScene in MediaCodecEncoderAdapterImpl
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(MediaCodecEncoderAdapterImplTest, MediaCodecEncoderAdapterImpl_NormalTest_003, TestSize.Level1)
{
    mediaCodecEncoderAdapterImpl->encoder_ = std::make_shared<MediaAVCodec::AVCodecVideoEncoderImpl>();
    EXPECT_EQ(mediaCodecEncoderAdapterImpl->Configure(config_), CodecCodeAdapter::ERROR);
    std::shared_ptr<CodecCallbackAdapter> callback = std::make_shared<EncoderCallbackAdapterMock>();
    EXPECT_EQ(mediaCodecEncoderAdapterImpl->SetCodecCallback(callback), CodecCodeAdapter::ERROR);
    EXPECT_EQ(mediaCodecEncoderAdapterImpl->Prepare(), CodecCodeAdapter::ERROR);
}

/**
 * @tc.name: MediaCodecEncoderAdapterImpl_SetCallbackDec_004.
 * @tc.desc: test of MediaCodecEncoderAdapterImpl::SetCodecCallback
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(MediaCodecEncoderAdapterImplTest, MediaCodecEncoderAdapterImpl_SetCodecCallback_004, TestSize.Level1)
{
    std::shared_ptr<CodecCallbackAdapter> callback = nullptr;
    EXPECT_EQ(mediaCodecEncoderAdapterImpl->SetCodecCallback(callback), CodecCodeAdapter::ERROR);
    callback = std::make_shared<EncoderCallbackAdapterMock>();
    EXPECT_EQ(mediaCodecEncoderAdapterImpl->SetCodecCallback(callback), CodecCodeAdapter::ERROR);
}

/**
 * @tc.name: MediaCodecEncoderAdapterImpl_GetTypeOrFlag_005.
 * @tc.desc: test of MediaCodecEncoderAdapterImpl::GetErrorType() GetBufferFlag()
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(MediaCodecEncoderAdapterImplTest, MediaCodecEncoderAdapterImpl_GetTypeOrFlag_005, TestSize.Level1)
{
    EXPECT_EQ(
        mediaCodecEncoderAdapterImpl->GetErrorType(OHOS::MediaAVCodec::AVCodecErrorType::AVCODEC_ERROR_EXTEND_START),
        ErrorType::CODEC_ERROR_EXTEND_START);
    EXPECT_EQ(
        mediaCodecEncoderAdapterImpl->GetBufferFlag(OHOS::MediaAVCodec::AVCodecBufferFlag::AVCODEC_BUFFER_FLAG_EOS),
        BufferFlag::CODEC_BUFFER_FLAG_EOS);
    AVCodecErrorType testAVCodecErrorType = static_cast<AVCodecErrorType>(100);
    EXPECT_EQ(mediaCodecEncoderAdapterImpl->GetErrorType(testAVCodecErrorType), ErrorType::CODEC_ERROR_INTERNAL);
    AVCodecBufferFlag testAVCodecBufferFlag = static_cast<AVCodecBufferFlag>(100);
    EXPECT_EQ(mediaCodecEncoderAdapterImpl->GetBufferFlag(testAVCodecBufferFlag), BufferFlag::CODEC_BUFFER_FLAG_NONE);
}

/**
 * @tc.name: MediaCodecEncoderAdapterImpl_OnError_006.
 * @tc.desc: test of MediaCodecEncoderAdapterImpl::GetErrorType() GetBufferFlag()
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(MediaCodecEncoderAdapterImplTest, MediaCodecEncoderAdapterImpl_OnError_006, TestSize.Level1)
{
    std::shared_ptr<CodecCallbackAdapter> cb = nullptr;
    std::shared_ptr<EncoderCallbackImpl> callbackImpl = std::make_shared<EncoderCallbackImpl>(cb);
    EXPECT_NE(callbackImpl, nullptr);
    std::shared_ptr<CodecCallbackAdapter> callback = std::make_shared<EncoderCallbackAdapterMock>();
    EXPECT_NE(callback, nullptr);
    callbackImpl->cb_ = callback;
    callbackImpl->OnError(OHOS::MediaAVCodec::AVCodecErrorType::AVCODEC_ERROR_EXTEND_START, 1);
    MediaAVCodec::Format fomat;
    callbackImpl->OnOutputFormatChanged(fomat);
    callbackImpl->OnInputBufferAvailable(1, nullptr);
    std::shared_ptr<Media::AVSharedMemory> memory = std::make_shared<Media::AVSharedMemoryBase>(1, 1.0, "test");
    callbackImpl->OnInputBufferAvailable(1, memory);
    AVCodecBufferInfo info;
    callbackImpl->OnOutputBufferAvailable(1, info, AVCodecBufferFlag::AVCODEC_BUFFER_FLAG_EOS, nullptr);
}

/**
 * @tc.name: MediaCodecEncoderAdapterImpl_GetList_001.
 * @tc.desc: test of MediaCodecListAdapterImpl::GetCodecCapability()
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(MediaCodecEncoderAdapterImplTest, MediaCodecEncoderAdapterImpl_GetList_001, TestSize.Level1)
{
    MediaCodecListAdapterImpl codecListImpl = MediaCodecListAdapterImpl::GetInstance();

    CapabilityDataAdapter capaData = codecListImpl.GetCodecCapability("test", true);
    EXPECT_EQ(capaData.maxWidth, 0);

    capaData = codecListImpl.GetCodecCapability("video/avc", true);
    EXPECT_NE(capaData.maxWidth, 0);
}

/**
 * @tc.name: MediaCodecEncoderAdapterImpl_Surface_001.
 * @tc.desc: test of ProducerSurfaceAdapterImpl::RequestBuffer()、FlushBuffer()
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(MediaCodecEncoderAdapterImplTest, MediaCodecEncoderAdapterImpl_Surface_001, TestSize.Level1)
{
    const std::string mimetype = "video/avc";
    auto surfaceAdapter = std::make_shared<ProducerSurfaceAdapterMock>();
    int32_t fence = -1;
    constexpr int32_t DEFAULT_STRIDE = 16;
    BufferRequestConfigAdapter configAdapter;
    configAdapter.width = config_.width;
    configAdapter.height = config_.height;
    configAdapter.strideAlignment = DEFAULT_STRIDE;
    std::shared_ptr<SurfaceBufferAdapter> SurfaceBufferAdapter = surfaceAdapter->RequestBuffer(fence, configAdapter);
    EXPECT_EQ(SurfaceBufferAdapter, nullptr);

    BufferFlushConfigAdapter fulshConfigAdapter;
    fulshConfigAdapter.x = 0;
    fulshConfigAdapter.y = 0;
    fulshConfigAdapter.w = configAdapter.width;
    fulshConfigAdapter.h = configAdapter.height;
    fulshConfigAdapter.timestamp = 0;
    int32_t ret = surfaceAdapter->FlushBuffer(SurfaceBufferAdapter, fence, fulshConfigAdapter);
    EXPECT_EQ(ret, 0);
}
} // namespace OHOS::NWeb
