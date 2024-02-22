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

#ifndef MEDIA_CODEC_DECODER_ADAPTER_H
#define MEDIA_CODEC_DECODER_ADAPTER_H

#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <queue>
#include <string>

#include "graphic_adapter.h"

namespace OHOS::NWeb {
enum class DecoderAdapterCode : int32_t {
    DECODER_OK = 0,
    DECODER_ERROR = 1,
    DECODER_RETRY = 2
};

struct DecoderFormat {
    int32_t width;
    int32_t height;
    double frameRate;
};

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

class DecoderCallbackAdapter {
public:
    DecoderCallbackAdapter() = default;

    virtual ~DecoderCallbackAdapter() = default;

    virtual void OnError(ErrorType errorType, int32_t errorCode) = 0;

    virtual void OnStreamChanged(const DecoderFormat &format) = 0;

    virtual void OnNeedInputData(uint32_t index, OhosBuffer buffer) = 0;

    virtual void OnNeedOutputData(uint32_t index, BufferInfo info, BufferFlag flag) = 0;
};

class MediaCodecDecoderAdapter {
public:
    MediaCodecDecoderAdapter() = default;

    virtual ~MediaCodecDecoderAdapter() = default;

    virtual DecoderAdapterCode CreateVideoDecoderByMime(const std::string& mimetype) = 0;

    virtual DecoderAdapterCode CreateVideoDecoderByName(const std::string& name) = 0;

    virtual DecoderAdapterCode ConfigureDecoder(const DecoderFormat& format) = 0;

    virtual DecoderAdapterCode SetParameterDecoder(const DecoderFormat &format) = 0;

    virtual DecoderAdapterCode SetOutputSurface(void* window) = 0;

    virtual DecoderAdapterCode PrepareDecoder() = 0;

    virtual DecoderAdapterCode StartDecoder() = 0;

    virtual DecoderAdapterCode StopDecoder() = 0;

    virtual DecoderAdapterCode FlushDecoder() = 0;

    virtual DecoderAdapterCode ResetDecoder() = 0;

    virtual DecoderAdapterCode ReleaseDecoder() = 0;

    virtual DecoderAdapterCode QueueInputBufferDec(uint32_t index, BufferInfo info, BufferFlag flag) = 0;

    virtual DecoderAdapterCode GetOutputFormatDec(DecoderFormat& format) = 0;

    virtual DecoderAdapterCode ReleaseOutputBufferDec(uint32_t index, bool isRender) = 0;

    virtual DecoderAdapterCode SetCallbackDec(const std::shared_ptr<DecoderCallbackAdapter> callback) = 0;
};
} // namespace OHOS::NWeb

#endif // MEDIA_CODEC_DECODER_ADAPTER_H
