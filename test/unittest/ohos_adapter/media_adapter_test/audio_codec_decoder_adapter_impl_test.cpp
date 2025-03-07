/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "audio_codec_decoder_adapter_impl.h"

#include "nweb_log.h"
#include "gtest/gtest.h"
#include <gmock/gmock.h>

using namespace testing;
using namespace testing::ext;
using testing::ext::TestSize;

namespace OHOS {
namespace NWeb {
const char *OH_AVCODEC_MIMETYPE_AUDIO_MPEG = "audio/mpeg";
const char *OH_AVCODEC_NAME_AUDIO_MPEG = "OH.Media.Codec.Decoder.Audio.Mpeg";

class AudioDecoderCallbackImplTest : public testing::Test {};

class AudioDecoderCallbackAdapterMock : public AudioDecoderCallbackAdapter {
public:
    AudioDecoderCallbackAdapterMock() = default;

    ~AudioDecoderCallbackAdapterMock() override = default;

    void OnError(int32_t errorCode) override {}

    void OnOutputFormatChanged() override {}

    void OnInputBufferAvailable(uint32_t index) override {}

    void OnOutputBufferAvailable(
        uint32_t index, uint8_t *bufferData, int32_t size, int64_t pts, int32_t offset, uint32_t flags) override {}
};

class AudioDecoderFormatAdapterMock : public AudioDecoderFormatAdapter {
public:
    AudioDecoderFormatAdapterMock() = default;

    ~AudioDecoderFormatAdapterMock() override = default;

    int32_t GetSampleRate() override
    {
        return sampleRate_;
    }

    int32_t GetChannelCount() override
    {
        return channelCount_;
    }

    int64_t GetBitRate() override
    {
        return bitRate_;
    }

    int32_t GetMaxInputSize() override
    {
        return maxInputSize_;
    }

    bool GetAACIsAdts() override
    {
        return aacIsAdts_;
    }

    int32_t GetAudioSampleFormat() override
    {
        return audioSampleFormat_;
    }

    int32_t GetIdentificationHeader() override
    {
        return idHeader_;
    }

    int32_t GetSetupHeader() override
    {
        return setupHeader_;
    }

    uint8_t* GetCodecConfig() override
    {
        return codecConfig_;
    }

    uint32_t GetCodecConfigSize() override
    {
        return codecConfigSize_;
    }

    void SetSampleRate(int32_t sampleRate) override
    {
        sampleRate_ = sampleRate;
    }

    void SetChannelCount(int32_t channelCount) override
    {
        channelCount_ = channelCount;
    }

    void SetBitRate(int64_t bitRate) override
    {
        bitRate_ = bitRate;
    }

    void SetMaxInputSize(int32_t maxInputSize) override
    {
        maxInputSize_ = maxInputSize;
    }

    void SetAudioSampleFormat(int32_t audioSampleFormat) override
    {
        audioSampleFormat_ = audioSampleFormat;
    }

    void SetAACIsAdts(bool isAdts) override
    {
        aacIsAdts_ = isAdts;
    }

    void SetIdentificationHeader(int32_t idHeader) override
    {
        idHeader_ = idHeader;
    }

    void SetSetupHeader(int32_t setupHeader) override
    {
        setupHeader_ = setupHeader;
    }

    void SetCodecConfig(uint8_t* codecConfig) override
    {
        codecConfig_ = codecConfig;
    }

    void SetCodecConfigSize(uint32_t size) override
    {
        codecConfigSize_ = size;
    }
private:
    int32_t sampleRate_ = 0;
    int32_t channelCount_ = 0;
    int64_t bitRate_ = 0;
    int32_t maxInputSize_ = 0;
    bool aacIsAdts_ = false;
    int32_t audioSampleFormat_ = 0;
    int32_t idHeader_ = 0;
    int32_t setupHeader_ = 0;
    uint8_t* codecConfig_ = nullptr;
    uint32_t codecConfigSize_ = 0;
};

// class AudioCencInfoAdapterMock : public AudioCencInfoAdapter {

/**
 * @tc.name: AudioDecoderCallbackImpl_NormalTest_001.
 * @tc.desc: test of AudioDecoderCallbackImpl::OnError() OnOutputFormatChanged() OnInputBufferAvailable()
             OnOutputBufferAvailable()
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(AudioDecoderCallbackImplTest, AudioDecoderCallbackImpl_NormalTest_001, TestSize.Level1)
{
    std::shared_ptr<AudioDecoderCallbackAdapterImpl> audioDecoderCallbackImpl =
        std::make_shared<AudioDecoderCallbackAdapterImpl>(nullptr);
    EXPECT_NE(audioDecoderCallbackImpl, nullptr);
    audioDecoderCallbackImpl->OnError(0);
    audioDecoderCallbackImpl->OnOutputFormatChanged();
    audioDecoderCallbackImpl->OnInputBufferAvailable(0);
    const int32_t BUFFER_SIZE = 10;
    uint8_t buffer[BUFFER_SIZE] = {0};
    audioDecoderCallbackImpl->OnOutputBufferAvailable(0, buffer, BUFFER_SIZE, 0, 0, 0);
}

class AudioCodecDecoderAdapterImplTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

protected:
    std::shared_ptr<AudioDecoderFormatAdapterMock> format_ = nullptr;
    std::shared_ptr<AudioCodecDecoderAdapterImpl> AudioCodecDecoderAdapterImpl_ = nullptr;
};

void AudioCodecDecoderAdapterImplTest::SetUpTestCase(void) {}

void AudioCodecDecoderAdapterImplTest::TearDownTestCase(void) {}

void AudioCodecDecoderAdapterImplTest::SetUp()
{
    EXPECT_EQ(AudioCodecDecoderAdapterImpl_, nullptr);
    AudioCodecDecoderAdapterImpl_ = std::make_unique<AudioCodecDecoderAdapterImpl>();
    EXPECT_NE(AudioCodecDecoderAdapterImpl_, nullptr);
    format_ = std::make_unique<AudioDecoderFormatAdapterMock>();
    EXPECT_NE(format_, nullptr);
}

void AudioCodecDecoderAdapterImplTest::TearDown(void)
{
    format_ = nullptr;
    AudioCodecDecoderAdapterImpl_ = nullptr;
}

/**
 * @tc.name: AudioCodecDecoderAdapterImpl_CreateAudioDecoderByName_001.
 * @tc.desc: test of AudioCodecDecoderAdapterImpl::CreateAudioDecoderByName() CreateAudioDecoderByMime()
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(AudioCodecDecoderAdapterImplTest, AudioCodecDecoderAdapterImpl_CreateAudioDecoderByName_001, TestSize.Level1)
{
    EXPECT_NE(AudioCodecDecoderAdapterImpl_, nullptr);

    // create decoder by invalid name or mimetype.
    std::string name = "testname";
    EXPECT_EQ(AudioCodecDecoderAdapterImpl_->CreateAudioDecoderByName(name), AudioDecoderAdapterCode::DECODER_ERROR);

    std::string mimetype = "testmimeType";
    EXPECT_EQ(AudioCodecDecoderAdapterImpl_->CreateAudioDecoderByMime(mimetype),
        AudioDecoderAdapterCode::DECODER_ERROR);

    // create decoder by normal name.
    name = std::string(OH_AVCODEC_NAME_AUDIO_MPEG);
    AudioDecoderAdapterCode ret = AudioCodecDecoderAdapterImpl_->CreateAudioDecoderByName(name);
    EXPECT_EQ(ret, AudioDecoderAdapterCode::DECODER_OK);

    // release decoder.
    ret = AudioCodecDecoderAdapterImpl_->ReleaseDecoder();
    EXPECT_EQ(ret, AudioDecoderAdapterCode::DECODER_OK);

    // create decoder by normal mimetype.
    mimetype = std::string(OH_AVCODEC_MIMETYPE_AUDIO_MPEG);
    ret = AudioCodecDecoderAdapterImpl_->CreateAudioDecoderByMime(mimetype);
    EXPECT_EQ(ret, AudioDecoderAdapterCode::DECODER_OK);

    // release decoder.
    ret = AudioCodecDecoderAdapterImpl_->ReleaseDecoder();
    EXPECT_EQ(ret, AudioDecoderAdapterCode::DECODER_OK);
}

/**
 * @tc.name: AudioCodecDecoderAdapterImpl_InvalidValueTest_002.
 * @tc.desc: test of InvalidValueScene in AudioCodecDecoderAdapterImpl
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(AudioCodecDecoderAdapterImplTest, AudioCodecDecoderAdapterImpl_InvalidValueTest_002, TestSize.Level1)
{
    format_->SetSampleRate(0);
    format_->SetChannelCount(0);
    format_->SetBitRate(0);
    format_->SetMaxInputSize(0);
    format_->SetAudioSampleFormat(0);
    EXPECT_EQ(AudioCodecDecoderAdapterImpl_->ConfigureDecoder(format_), AudioDecoderAdapterCode::DECODER_ERROR);
    EXPECT_EQ(AudioCodecDecoderAdapterImpl_->SetParameterDecoder(format_), AudioDecoderAdapterCode::DECODER_ERROR);

    EXPECT_EQ(AudioCodecDecoderAdapterImpl_->SetCallbackDec(nullptr), AudioDecoderAdapterCode::DECODER_ERROR);

    EXPECT_EQ(AudioCodecDecoderAdapterImpl_->QueueInputBufferDec(0, 0, nullptr, 0, nullptr, false,
        BufferFlag::CODEC_BUFFER_FLAG_NONE), AudioDecoderAdapterCode::DECODER_ERROR);
    EXPECT_EQ(AudioCodecDecoderAdapterImpl_->GetOutputFormatDec(format_), AudioDecoderAdapterCode::DECODER_ERROR);
    EXPECT_EQ(AudioCodecDecoderAdapterImpl_->ReleaseOutputBufferDec(0), AudioDecoderAdapterCode::DECODER_ERROR);
    EXPECT_EQ(AudioCodecDecoderAdapterImpl_->PrepareDecoder(), AudioDecoderAdapterCode::DECODER_ERROR);
    EXPECT_EQ(AudioCodecDecoderAdapterImpl_->StartDecoder(), AudioDecoderAdapterCode::DECODER_ERROR);
    EXPECT_EQ(AudioCodecDecoderAdapterImpl_->StopDecoder(), AudioDecoderAdapterCode::DECODER_ERROR);
    EXPECT_EQ(AudioCodecDecoderAdapterImpl_->FlushDecoder(), AudioDecoderAdapterCode::DECODER_ERROR);
    EXPECT_EQ(AudioCodecDecoderAdapterImpl_->ResetDecoder(), AudioDecoderAdapterCode::DECODER_ERROR);
    EXPECT_EQ(AudioCodecDecoderAdapterImpl_->SetDecryptionConfig(nullptr, false),
        AudioDecoderAdapterCode::DECODER_ERROR);
}

/**
 * @tc.name: AudioCodecDecoderAdapterImpl_NormalValueTest_003.
 * @tc.desc: test of NormalScene in AudioCodecDecoderAdapterImpl
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(AudioCodecDecoderAdapterImplTest, AudioCodecDecoderAdapterImpl_NormalValueTest_003, TestSize.Level1)
{
    // create decoder by normal mimetype.
    std::string mimetype = std::string(OH_AVCODEC_MIMETYPE_AUDIO_MPEG);
    AudioDecoderAdapterCode ret = AudioCodecDecoderAdapterImpl_->CreateAudioDecoderByMime(mimetype);
    EXPECT_EQ(ret, AudioDecoderAdapterCode::DECODER_OK);

    // config decoder.
    constexpr uint32_t DEFAULT_SAMPLERATE = 44100;
    constexpr uint32_t DEFAULT_BITRATE = 32000;
    constexpr uint32_t DEFAULT_CHANNEL_COUNT = 2;
    constexpr uint32_t DEFAULT_MAX_INPUT_SIZE = 1152;
    format_->SetSampleRate(DEFAULT_SAMPLERATE);
    format_->SetChannelCount(DEFAULT_CHANNEL_COUNT);
    format_->SetBitRate(DEFAULT_BITRATE);
    format_->SetMaxInputSize(DEFAULT_MAX_INPUT_SIZE);
    EXPECT_EQ(AudioCodecDecoderAdapterImpl_->ConfigureDecoder(format_), AudioDecoderAdapterCode::DECODER_OK);

    // set callback for decoding.
    std::shared_ptr<AudioDecoderCallbackAdapter> callback = std::make_shared<AudioDecoderCallbackAdapterMock>();
    EXPECT_EQ(AudioCodecDecoderAdapterImpl_->SetCallbackDec(callback), AudioDecoderAdapterCode::DECODER_OK);

    // prepare decoder.
    EXPECT_EQ(AudioCodecDecoderAdapterImpl_->PrepareDecoder(), AudioDecoderAdapterCode::DECODER_OK);
    EXPECT_EQ(AudioCodecDecoderAdapterImpl_->StartDecoder(), AudioDecoderAdapterCode::DECODER_OK);
    EXPECT_EQ(AudioCodecDecoderAdapterImpl_->SetParameterDecoder(format_), AudioDecoderAdapterCode::DECODER_OK);
    EXPECT_EQ(AudioCodecDecoderAdapterImpl_->FlushDecoder(), AudioDecoderAdapterCode::DECODER_OK);
    EXPECT_EQ(AudioCodecDecoderAdapterImpl_->StopDecoder(), AudioDecoderAdapterCode::DECODER_OK);
    EXPECT_EQ(AudioCodecDecoderAdapterImpl_->ResetDecoder(), AudioDecoderAdapterCode::DECODER_OK);
    EXPECT_EQ(AudioCodecDecoderAdapterImpl_->SetCallbackDec(callback), AudioDecoderAdapterCode::DECODER_OK);
}
}
} // namespace OHOS::NWeb
