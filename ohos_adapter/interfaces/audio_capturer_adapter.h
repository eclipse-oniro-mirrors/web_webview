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

#ifndef AUDIO_CAPTURE_ADAPTER_H
#define AUDIO_CAPTURE_ADAPTER_H

#include <memory>
#include <string>
#include "audio_renderer_adapter.h"

namespace OHOS::NWeb {
enum class AudioAdapterSourceType {
    SOURCE_TYPE_INVALID = -1,
    SOURCE_TYPE_MIC,
    SOURCE_TYPE_VOICE_RECOGNITION = 1,
    SOURCE_TYPE_VOICE_COMMUNICATION = 7,
    SOURCE_TYPE_ULTRASONIC = 8
};

struct AudioAdapterCapturerOptions {
    AudioAdapterSamplingRate samplingRate;
    AudioAdapterEncodingType encoding;
    AudioAdapterSampleFormat format;
    AudioAdapterChannel channels;
    AudioAdapterSourceType sourceType;
    int32_t capturerFlags;
};

struct BufferDescAdapter {
    uint8_t* buffer;
    size_t bufLength;
    size_t dataLength;
};

class AudioCapturerReadCallbackAdapter {
public:
    AudioCapturerReadCallbackAdapter() = default;

    virtual ~AudioCapturerReadCallbackAdapter() = default;

    virtual void OnReadData(size_t length) = 0;
};

class AudioCapturerAdapter {
public:
    AudioCapturerAdapter() = default;

    virtual ~AudioCapturerAdapter() = default;

    virtual int32_t Create(const AudioAdapterCapturerOptions &capturerOptions,
        std::string cachePath = std::string()) = 0;

    virtual bool Start() = 0;

    virtual bool Stop() = 0;

    virtual bool Release() = 0;

    virtual int32_t SetCapturerReadCallback(
        std::shared_ptr<AudioCapturerReadCallbackAdapter> callbck) = 0;

    virtual int32_t GetBufferDesc(BufferDescAdapter &buffferDesc) = 0;

    virtual int32_t Enqueue(const BufferDescAdapter &bufferDesc) = 0;

    virtual int32_t GetFrameCount(uint32_t &frameCount) = 0;

    virtual int64_t GetAudioTime() = 0;
};
} // namespace OHOS::NWeb

#endif // AUDIO_CAPTURE_ADAPTER_H
