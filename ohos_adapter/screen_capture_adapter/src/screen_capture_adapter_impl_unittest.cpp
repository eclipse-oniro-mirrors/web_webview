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

#include <cstdint>
#include <cstring>
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/gmock/include/gmock/gmock.h"
#include <thread>

#define private public
#include "screen_capture_adapter_impl.h"
#undef private

namespace OHOS {
namespace NWeb {

class MockAudioCaptureInfoAdapter : public AudioCaptureInfoAdapter {
public:
    MockAudioCaptureInfoAdapter() = default;

    int32_t GetAudioSampleRate() override
    {
        return audioSampleRate;
    }

    int32_t GetAudioChannels() override
    {
        return audioChannels;
    }

    AudioCaptureSourceTypeAdapter GetAudioSource() override
    {
        return audioSource;
    }

    int32_t audioSampleRate;
    int32_t audioChannels;
    AudioCaptureSourceTypeAdapter audioSource = AudioCaptureSourceTypeAdapter::SOURCE_DEFAULT;
};

class MockAudioEncInfoAdapter : public AudioEncInfoAdapter {
public:
    MockAudioEncInfoAdapter() = default;

    int32_t GetAudioBitrate() override
    {
        return audioBitrate;
    }

    AudioCodecFormatAdapter GetAudioCodecformat() override
    {
        return audioCodecformat;
    }

    int32_t audioBitrate = 0;
    AudioCodecFormatAdapter audioCodecformat = AudioCodecFormatAdapter::AUDIO_DEFAULT;
};

class MockAudioInfoAdapter : public AudioInfoAdapter {
public:
    MockAudioInfoAdapter() = default;

    std::shared_ptr<AudioCaptureInfoAdapter> GetMicCapInfo() override
    {
        return micCapInfo;
    }

    std::shared_ptr<AudioCaptureInfoAdapter> GetInnerCapInfo() override
    {
        return innerCapInfo;
    }

    std::shared_ptr<AudioEncInfoAdapter> GetAudioEncInfo() override
    {
        return audioEncInfo;
    }

    std::shared_ptr<MockAudioCaptureInfoAdapter> micCapInfo = nullptr;
    std::shared_ptr<MockAudioCaptureInfoAdapter> innerCapInfo = nullptr;
    std::shared_ptr<MockAudioEncInfoAdapter> audioEncInfo = nullptr;
};

class MockVideoCaptureInfoAdapter : public VideoCaptureInfoAdapter {
public:
    MockVideoCaptureInfoAdapter() = default;

    uint64_t GetDisplayId() override
    {
        return displayId;
    }

    std::list<int32_t> GetTaskIDs() override
    {
        return taskIDs;
    }

    int32_t GetVideoFrameWidth() override
    {
        return videoFrameWidth;
    }

    int32_t GetVideoFrameHeight() override
    {
        return videoFrameHeight;
    }

    VideoSourceTypeAdapter GetVideoSourceType() override
    {
        return videoSource;
    }

    uint64_t displayId = 0;
    std::list<int32_t> taskIDs;
    int32_t videoFrameWidth = 0;
    int32_t videoFrameHeight = 0;
    VideoSourceTypeAdapter videoSource = VideoSourceTypeAdapter::VIDEO_SOURCE_SURFACE_RGBA;
};

class MockVideoEncInfoAdapter : public VideoEncInfoAdapter {
public:
    MockVideoEncInfoAdapter() = default;

    VideoCodecFormatAdapter GetVideoCodecFormat() override
    {
        return videoCodec;
    }

    int32_t GetVideoBitrate() override
    {
        return videoBitrate;
    }

    int32_t GetVideoFrameRate() override
    {
        return videoFrameRate;
    }

    VideoCodecFormatAdapter videoCodec = VideoCodecFormatAdapter::VIDEO_DEFAULT;
    int32_t videoBitrate = 0;
    int32_t videoFrameRate = 0;
};

class MockVideoInfoAdapter : public VideoInfoAdapter {
public:
    MockVideoInfoAdapter() = default;

    std::shared_ptr<VideoCaptureInfoAdapter> GetVideoCapInfo()
    {
        return videoCapInfo;
    }

    std::shared_ptr<VideoEncInfoAdapter> GetVideoEncInfo()
    {
        return videoEncInfo;
    }

    std::shared_ptr<MockVideoCaptureInfoAdapter> videoCapInfo = nullptr;
    std::shared_ptr<MockVideoEncInfoAdapter> videoEncInfo = nullptr;
};

class MockRecorderInfoAdapter : public RecorderInfoAdapter {
public:
    MockRecorderInfoAdapter() = default;

    std::string GetUrl() override
    {
        return url;
    }

    ContainerFormatTypeAdapter GetFileFormat() override
    {
        return fileFormat;
    }

    std::string url = "";
    ContainerFormatTypeAdapter fileFormat = ContainerFormatTypeAdapter::CFT_MPEG_4A_TYPE;
};

class MockScreenCaptureConfigAdapter : public ScreenCaptureConfigAdapter {
public:
    MockScreenCaptureConfigAdapter() = default;

    CaptureModeAdapter GetCaptureMode() override
    {
        return captureMode;
    }

    DataTypeAdapter GetDataType() override
    {
        return dataType;
    }

    std::shared_ptr<AudioInfoAdapter> GetAudioInfo()
    {
        return audioInfo;
    }

    std::shared_ptr<VideoInfoAdapter> GetVideoInfo()
    {
        return videoInfo;
    }

    std::shared_ptr<RecorderInfoAdapter> GetRecorderInfo()
    {
        return recorderInfo;
    }

    CaptureModeAdapter captureMode = CaptureModeAdapter::CAPTURE_INVAILD;
    DataTypeAdapter dataType = DataTypeAdapter::INVAILD_DATA_TYPE;
    std::shared_ptr<MockAudioInfoAdapter> audioInfo = nullptr;
    std::shared_ptr<MockVideoInfoAdapter> videoInfo = nullptr;
    std::shared_ptr<MockRecorderInfoAdapter> recorderInfo = nullptr;
};

namespace {
constexpr int32_t AUDIO_SAMPLE_RATE = 16000;
constexpr int32_t AUDIO_CHANNELS = 2;
constexpr int32_t SCREEN_WIDTH = 1080;
constexpr int32_t SCREEN_HEIGHT = 720;
std::shared_ptr<ScreenCaptureAdapterImpl> g_screenCapture = nullptr;
std::shared_ptr<MockAudioCaptureInfoAdapter> g_micCapInfo = nullptr;
std::shared_ptr<MockAudioCaptureInfoAdapter> g_innerCapInfo = nullptr;
std::shared_ptr<MockAudioEncInfoAdapter> g_audioEncInfo = nullptr;
std::shared_ptr<MockAudioInfoAdapter> g_audioInfo = nullptr;
std::shared_ptr<MockVideoCaptureInfoAdapter> g_videoCaptureInfo = nullptr;
std::shared_ptr<MockVideoEncInfoAdapter> g_videoEncInfo = nullptr;
std::shared_ptr<MockVideoInfoAdapter> g_videoInfo = nullptr;
std::shared_ptr<MockRecorderInfoAdapter> g_recorderInfo = nullptr;
std::shared_ptr<MockScreenCaptureConfigAdapter> g_screenCaptureConfig = nullptr;

class ScreenCaptureCallbackAdapterTest : public ScreenCaptureCallbackAdapter {
public:
    ScreenCaptureCallbackAdapterTest() = default;
    ~ScreenCaptureCallbackAdapterTest() override = default;

    void OnError(int32_t errorCode) override
    {
        (void)errorCode;
    }

    void OnAudioBufferAvailable(bool isReady, AudioCaptureSourceTypeAdapter type) override
    {
        (void)isReady;
        (void)type;
    }

    void OnVideoBufferAvailable(bool isReady) override
    {
        if (!isReady || !g_screenCapture) {
            return;
        }
        std::shared_ptr<SurfaceBufferAdapter> buffer = g_screenCapture->AcquireVideoBuffer();
        if (buffer) {
            g_screenCapture->ReleaseVideoBuffer();
        }
    }
};
} // namespace

class ScreenCaptureAdapterImplTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void) {}

    void SetUp() override {}

    void TearDown() override {}
};

void ScreenCaptureAdapterImplTest::SetUpTestCase(void)
{
    g_screenCapture = std::make_shared<ScreenCaptureAdapterImpl>();
    g_micCapInfo = std::make_shared<MockAudioCaptureInfoAdapter>();
    g_innerCapInfo = std::make_shared<MockAudioCaptureInfoAdapter>();
    g_audioEncInfo = std::make_shared<MockAudioEncInfoAdapter>();
    g_audioInfo = std::make_shared<MockAudioInfoAdapter>();
    g_videoCaptureInfo = std::make_shared<MockVideoCaptureInfoAdapter>();
    g_videoEncInfo = std::make_shared<MockVideoEncInfoAdapter>();
    g_videoInfo = std::make_shared<MockVideoInfoAdapter>();
    g_recorderInfo = std::make_shared<MockRecorderInfoAdapter>();
    g_screenCaptureConfig = std::make_shared<MockScreenCaptureConfigAdapter>();

    EXPECT_NE(g_screenCapture, nullptr);
    EXPECT_NE(g_micCapInfo, nullptr);
    EXPECT_NE(g_innerCapInfo, nullptr);
    EXPECT_NE(g_audioEncInfo, nullptr);
    EXPECT_NE(g_audioInfo, nullptr);
    EXPECT_NE(g_videoCaptureInfo, nullptr);
    EXPECT_NE(g_videoEncInfo, nullptr);
    EXPECT_NE(g_videoInfo, nullptr);
    EXPECT_NE(g_recorderInfo, nullptr);
    EXPECT_NE(g_screenCaptureConfig, nullptr);
    int32_t result = g_screenCapture->Init(nullptr);
    EXPECT_EQ(result, -1);

    g_screenCaptureConfig->captureMode = CaptureModeAdapter::CAPTURE_HOME_SCREEN;
    g_screenCaptureConfig->dataType = DataTypeAdapter::ORIGINAL_STREAM_DATA_TYPE;
    g_micCapInfo->audioSampleRate = AUDIO_SAMPLE_RATE;
    g_micCapInfo->audioChannels = AUDIO_CHANNELS;
    g_innerCapInfo->audioSampleRate = AUDIO_SAMPLE_RATE;
    g_innerCapInfo->audioChannels = AUDIO_CHANNELS;
    g_audioInfo->micCapInfo = g_micCapInfo;
    g_audioInfo->innerCapInfo = g_innerCapInfo;
    g_audioInfo->audioEncInfo = g_audioEncInfo;
    g_videoCaptureInfo->videoFrameWidth = SCREEN_WIDTH;
    g_videoCaptureInfo->videoFrameHeight = SCREEN_HEIGHT;
    g_videoInfo->videoCapInfo = g_videoCaptureInfo;
    g_videoInfo->videoEncInfo = g_videoEncInfo;
    result = g_screenCapture->Init(g_screenCaptureConfig);
    EXPECT_EQ(result, 0);
    g_screenCaptureConfig->audioInfo = g_audioInfo;
    result = g_screenCapture->Init(g_screenCaptureConfig);
    EXPECT_EQ(result, 0);
    g_screenCaptureConfig->videoInfo = g_videoInfo;
    result = g_screenCapture->Init(g_screenCaptureConfig);
    EXPECT_EQ(result, 0);
    g_screenCaptureConfig->recorderInfo = g_recorderInfo;
    result = g_screenCapture->Init(g_screenCaptureConfig);
    EXPECT_EQ(result, 0);
}

/**
 * @tc.name: ScreenCaptureAdapterImplTest_Init_001
 * @tc.desc: Init.
 * @tc.type: FUNC
 * @tc.require: AR000I7I57
 */
TEST_F(ScreenCaptureAdapterImplTest, ScreenCaptureAdapterImplTest_Init_001)
{
    auto adapterImpl = std::make_shared<ScreenCaptureAdapterImpl>();
    EXPECT_NE(adapterImpl, nullptr);
    g_screenCaptureConfig->captureMode = CaptureModeAdapter::CAPTURE_INVAILD;
    g_screenCaptureConfig->dataType = DataTypeAdapter::INVAILD_DATA_TYPE;
    g_screenCaptureConfig->audioInfo->micCapInfo->audioSampleRate = AUDIO_SAMPLE_RATE;
    g_screenCaptureConfig->audioInfo->micCapInfo->audioChannels = AUDIO_CHANNELS;
    g_screenCaptureConfig->audioInfo->innerCapInfo->audioSampleRate = AUDIO_SAMPLE_RATE;
    g_screenCaptureConfig->audioInfo->innerCapInfo->audioChannels = AUDIO_CHANNELS;
    g_screenCaptureConfig->videoInfo->videoCapInfo->videoFrameWidth = SCREEN_WIDTH;
    g_screenCaptureConfig->videoInfo->videoCapInfo->videoFrameHeight = SCREEN_HEIGHT;
    g_screenCaptureConfig->audioInfo->micCapInfo->audioSource = AudioCaptureSourceTypeAdapter::SOURCE_INVALID;
    g_screenCaptureConfig->audioInfo->audioEncInfo->audioCodecformat = AudioCodecFormatAdapter::AUDIO_DEFAULT;
    g_screenCaptureConfig->videoInfo->videoCapInfo->videoSource = VideoSourceTypeAdapter::VIDEO_SOURCE_SURFACE_YUV;
    g_screenCaptureConfig->videoInfo->videoEncInfo->videoCodec = VideoCodecFormatAdapter::VIDEO_DEFAULT;
    int32_t result = adapterImpl->Init(g_screenCaptureConfig);
    EXPECT_EQ(result, -1);
    g_screenCaptureConfig->captureMode = CaptureModeAdapter::CAPTURE_HOME_SCREEN;
    g_screenCaptureConfig->dataType = DataTypeAdapter::ENCODED_STREAM_DATA_TYPE;
    g_screenCaptureConfig->audioInfo->micCapInfo->audioSource = AudioCaptureSourceTypeAdapter::SOURCE_DEFAULT;
    g_screenCaptureConfig->audioInfo->audioEncInfo->audioCodecformat = AudioCodecFormatAdapter::AAC_LC;
    g_screenCaptureConfig->videoInfo->videoCapInfo->videoSource = VideoSourceTypeAdapter::VIDEO_SOURCE_SURFACE_ES;
    g_screenCaptureConfig->videoInfo->videoEncInfo->videoCodec = VideoCodecFormatAdapter::H264;
    result = adapterImpl->Init(g_screenCaptureConfig);
    EXPECT_EQ(result, -1);
    g_screenCaptureConfig->captureMode = CaptureModeAdapter::CAPTURE_SPECIFIED_SCREEN;
    g_screenCaptureConfig->dataType = DataTypeAdapter::CAPTURE_FILE_DATA_TYPE;
    g_screenCaptureConfig->audioInfo->micCapInfo->audioSource = AudioCaptureSourceTypeAdapter::MIC;
    g_screenCaptureConfig->audioInfo->audioEncInfo->audioCodecformat = AudioCodecFormatAdapter::AUDIO_CODEC_FORMAT_BUTT;
    g_screenCaptureConfig->videoInfo->videoCapInfo->videoSource = VideoSourceTypeAdapter::VIDEO_SOURCE_SURFACE_RGBA;
    g_screenCaptureConfig->videoInfo->videoEncInfo->videoCodec = VideoCodecFormatAdapter::H265;
    result = adapterImpl->Init(g_screenCaptureConfig);
    EXPECT_EQ(result, -1);
    g_screenCaptureConfig->captureMode = CaptureModeAdapter::CAPTURE_SPECIFIED_WINDOW;
    g_screenCaptureConfig->dataType = DataTypeAdapter::ORIGINAL_STREAM_DATA_TYPE;
    g_screenCaptureConfig->audioInfo->micCapInfo->audioSource = AudioCaptureSourceTypeAdapter::ALL_PLAYBACK;
    g_screenCaptureConfig->videoInfo->videoCapInfo->videoSource = VideoSourceTypeAdapter::VIDEO_SOURCE_BUTT;
    g_screenCaptureConfig->videoInfo->videoEncInfo->videoCodec = VideoCodecFormatAdapter::MPEG4;
    result = adapterImpl->Init(g_screenCaptureConfig);
    EXPECT_EQ(result, -1);
    g_screenCaptureConfig->audioInfo->micCapInfo->audioSource = AudioCaptureSourceTypeAdapter::APP_PLAYBACK;
    g_screenCaptureConfig->videoInfo->videoEncInfo->videoCodec = VideoCodecFormatAdapter::VP8;
    result = adapterImpl->Init(g_screenCaptureConfig);
    EXPECT_EQ(result, -1);
    g_screenCaptureConfig->videoInfo->videoEncInfo->videoCodec = VideoCodecFormatAdapter::VP9;
    result = adapterImpl->Init(g_screenCaptureConfig);
    EXPECT_EQ(result, -1);
}

/**
 * @tc.name: ScreenCaptureAdapterImplTest_SetMicrophoneEnable_002
 * @tc.desc: SetMicrophoneEnable.
 * @tc.type: FUNC
 * @tc.require: AR000I7I57
 */
TEST_F(ScreenCaptureAdapterImplTest, ScreenCaptureAdapterImplTest_SetMicrophoneEnable_002)
{
    auto adapterImpl = std::make_shared<ScreenCaptureAdapterImpl>();
    EXPECT_NE(adapterImpl, nullptr);
    int32_t result = adapterImpl->SetMicrophoneEnable(false);
    EXPECT_EQ(result, -1);
    result = g_screenCapture->SetMicrophoneEnable(false);
    EXPECT_EQ(result, 0);
    result = g_screenCapture->SetMicrophoneEnable(true);
    EXPECT_EQ(result, 0);
}

/**
 * @tc.name: ScreenCaptureAdapterImplTest_AcquireVideoBuffer_003
 * @tc.desc: AcquireVideoBuffer.
 * @tc.type: FUNC
 * @tc.require: AR000I7I57
 */
TEST_F(ScreenCaptureAdapterImplTest, ScreenCaptureAdapterImplTest_AcquireVideoBuffer_003)
{
    auto adapterImpl = std::make_shared<ScreenCaptureAdapterImpl>();
    EXPECT_NE(adapterImpl, nullptr);
    std::shared_ptr<SurfaceBufferAdapter> buffer = adapterImpl->AcquireVideoBuffer();
    EXPECT_EQ(buffer, nullptr);
    int32_t result = adapterImpl->ReleaseVideoBuffer();
    EXPECT_EQ(result, -1);
}

/**
 * @tc.name: ScreenCaptureAdapterImplTest_Capture_004
 * @tc.desc: Capture.
 * @tc.type: FUNC
 * @tc.require: AR000I7I57
 */
TEST_F(ScreenCaptureAdapterImplTest, ScreenCaptureAdapterImplTest_Capture_004)
{
    auto adapterImpl = std::make_shared<ScreenCaptureAdapterImpl>();
    EXPECT_NE(adapterImpl, nullptr);
    int32_t result = adapterImpl->StartCapture();
    EXPECT_EQ(result, -1);
    result = adapterImpl->StopCapture();
    EXPECT_EQ(result, -1);
    auto callbackAdapter = std::make_shared<ScreenCaptureCallbackAdapterTest>();
    EXPECT_NE(callbackAdapter, nullptr);
    result = g_screenCapture->SetCaptureCallback(callbackAdapter);
    EXPECT_EQ(result, 0);
}
} // namespace NWeb
} // namespace OHOS