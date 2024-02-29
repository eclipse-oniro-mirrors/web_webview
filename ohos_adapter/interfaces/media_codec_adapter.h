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

#ifndef MEDIA_CODEC_ADAPTER_H
#define MEDIA_CODEC_ADAPTER_H

#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <queue>
#include <string>

#include "graphic_adapter.h"

namespace OHOS::NWeb {

enum class CodecCodeAdapter {
    OK = 0,
    ERROR = 1,
    RETRY = 2
};

typedef struct CapabilityDataAdapterTag {
    int32_t maxWidth;
    int32_t maxHeight;
    int32_t maxframeRate;
} CapabilityDataAdapter;

typedef struct CodecFormatAdapterTag {
    int32_t width;
    int32_t height;
}CodecFormatAdapter;

enum class ErrorType : int32_t {
    CODEC_ERROR_INTERNAL,
    CODEC_ERROR_EXTEND_START = 0X10000,
};

struct BufferInfo {
    int64_t presentationTimeUs = 0;
    int32_t size = 0;
    int32_t offset = 0;
};

enum class BufferFlag : uint32_t {
    CODEC_BUFFER_FLAG_NONE = 0,
    CODEC_BUFFER_FLAG_EOS = 1 << 0,
    CODEC_BUFFER_FLAG_SYNC_FRAME = 1 << 1,
    CODEC_BUFFER_FLAG_PARTIAL_FRAME = 1 << 2,
    CODEC_BUFFER_FLAG_CODEC_DATA = 1 << 3,
};

struct OhosBuffer {
    uint8_t *addr; 

    uint32_t bufferSize;
};

struct CodecConfigPara {
    int32_t width;
    int32_t height;
    int64_t bitRate;
    double frameRate;
};

class CodecCallbackAdapter {
public:
    CodecCallbackAdapter() = default;

    virtual ~CodecCallbackAdapter() = default;

    virtual void OnError(ErrorType errorType, int32_t errorCode) = 0;

    virtual void OnStreamChanged(const CodecFormatAdapter &format) = 0;

    virtual void OnNeedInputData(uint32_t index, OhosBuffer buffer) = 0;

    virtual void OnNeedOutputData(uint32_t index, BufferInfo info, BufferFlag flag, OhosBuffer buffer) = 0;
};

class MediaCodecAdapter {
public:
    MediaCodecAdapter() = default;

    virtual ~MediaCodecAdapter() = default;

    virtual CodecCodeAdapter CreateVideoCodecByMime(const std::string mimetype) = 0;

    virtual CodecCodeAdapter CreateVideoCodecByName(const std::string name) = 0;

    virtual CodecCodeAdapter SetCodecCallback(const std::shared_ptr<CodecCallbackAdapter> callback) = 0;

    virtual CodecCodeAdapter Configure(const CodecConfigPara &config) = 0;

    virtual CodecCodeAdapter Prepare() = 0;

    virtual CodecCodeAdapter Start() = 0;

    virtual CodecCodeAdapter Stop() = 0;

    virtual CodecCodeAdapter Reset() = 0;

    virtual CodecCodeAdapter Release() = 0;

    virtual std::shared_ptr<ProducerSurfaceAdapter> CreateInputSurface() = 0;

    virtual CodecCodeAdapter ReleaseOutputBuffer(uint32_t index, bool isRender) = 0;

    virtual CodecCodeAdapter RequestKeyFrameSoon() = 0;
};

class MediaCodecListAdapter {
public:
    MediaCodecListAdapter() = default;

    virtual ~MediaCodecListAdapter() = default;

    virtual CapabilityDataAdapter GetCodecCapability(const std::string &mime, const bool isCodec) = 0;

};
}
#endif