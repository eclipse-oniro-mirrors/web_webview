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

#include "mediacodecdecoderadapterimpl_fuzzer.h"

#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>

#include "avsharedmemory.h"
#include "avsharedmemorybase.h"
#include "media_codec_decoder_adapter_impl.h"

using namespace OHOS::NWeb;

namespace OHOS {
constexpr uint8_t MAX_STRING_LENGTH = 255;

class DecoderCallbackAdapterMock : public DecoderCallbackAdapter {
public:
    DecoderCallbackAdapterMock() = default;

    ~DecoderCallbackAdapterMock() override = default;

    void OnError(ErrorType errorType, int32_t errorCode) override {}

    void OnStreamChanged(int32_t width, int32_t height, double frameRate) override {}

    void OnNeedInputData(uint32_t index, std::shared_ptr<OhosBufferAdapter> buffer) override {}

    void OnNeedOutputData(uint32_t index, std::shared_ptr<BufferInfoAdapter> info, BufferFlag flag) override {}
};

class DecoderFormatAdapterMock : public DecoderFormatAdapter {
public:
    DecoderFormatAdapterMock() = default;

    int32_t GetWidth() override
    {
        return width;
    }

    int32_t GetHeight() override
    {
        return height;
    }

    double GetFrameRate() override
    {
        return frameRate;
    }

    void SetWidth(int32_t w) override
    {
        width = w;
    }

    void SetHeight(int32_t h) override
    {
        height = h;
    }

    void SetFrameRate(double fr) override
    {
        frameRate = fr;
    }

    int32_t width;
    int32_t height;
    double frameRate;
};

bool MediaCodecDecoderAdapterImplFuzzTest(const uint8_t* data, size_t size)
{
    NWeb::MediaCodecDecoderAdapterImpl mediaCodecDecoderAdapterImpl;
    NWeb::DecoderAdapterCode code = mediaCodecDecoderAdapterImpl.CreateVideoDecoderByMime("testmimeType");
    std::shared_ptr<NWeb::DecoderFormatAdapter> format = std::make_unique<DecoderFormatAdapterMock>();
    FuzzedDataProvider dataProvider(data, size);
    std::string stringParam = dataProvider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    code = mediaCodecDecoderAdapterImpl.CreateVideoDecoderByName(stringParam);
    code = mediaCodecDecoderAdapterImpl.ConfigureDecoder(format);
    code = mediaCodecDecoderAdapterImpl.SetParameterDecoder(format);

    void* window = nullptr;
    code = mediaCodecDecoderAdapterImpl.SetOutputSurface(window);
    code = mediaCodecDecoderAdapterImpl.PrepareDecoder();
    code = mediaCodecDecoderAdapterImpl.StartDecoder();
    code = mediaCodecDecoderAdapterImpl.StopDecoder();
    code = mediaCodecDecoderAdapterImpl.FlushDecoder();
    code = mediaCodecDecoderAdapterImpl.ResetDecoder();
    code = mediaCodecDecoderAdapterImpl.ReleaseDecoder();

    int32_t intParam = dataProvider.ConsumeIntegralInRange<int32_t>(0, 10000);
    uint32_t uintParam = dataProvider.ConsumeIntegralInRange<uint32_t>(0, 10000);
    code = mediaCodecDecoderAdapterImpl.QueueInputBufferDec(
        uintParam, 0, intParam, intParam, BufferFlag::CODEC_BUFFER_FLAG_NONE);
    code = mediaCodecDecoderAdapterImpl.GetOutputFormatDec(format);
    code = mediaCodecDecoderAdapterImpl.ReleaseOutputBufferDec(uintParam, true);

    mediaCodecDecoderAdapterImpl.OnError(uintParam);
    mediaCodecDecoderAdapterImpl.OnOutputFormatChanged(nullptr);
    mediaCodecDecoderAdapterImpl.OnInputBufferAvailable(uintParam, nullptr);
    mediaCodecDecoderAdapterImpl.OnOutputBufferAvailable(uintParam, nullptr);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::MediaCodecDecoderAdapterImplFuzzTest(data, size);
    return 0;
}