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

#ifndef ARK_MEDIA_CODEC_DECODER_ADAPTER_H
#define ARK_MEDIA_CODEC_DECODER_ADAPTER_H

#pragma once

#include <cstdint>

#include "include/ark_web_base_ref_counted.h"
#include "include/ark_web_types.h"
#include "media_codec_decoder_adapter.h"

using ArkDecoderFormat = OHOS::NWeb::DecoderFormat;
using ArkBufferInfo = OHOS::NWeb::BufferInfo;
using ArkOhosBuffer = OHOS::NWeb::OhosBuffer;

namespace OHOS::ArkWeb {

/*--web engine(source=client)--*/
class ArkDecoderCallbackAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkDecoderCallbackAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkDecoderCallbackAdapter() = default;

    /*--web engine()--*/
    virtual void OnError(int32_t errorType, int32_t errorCode) = 0;

    /*--web engine()--*/
    virtual void OnStreamChanged(const ArkDecoderFormat& format) = 0;

    /*--web engine()--*/
    virtual void OnNeedInputData(uint32_t index, ArkOhosBuffer buffer) = 0;

    /*--web engine()--*/
    virtual void OnNeedOutputData(uint32_t index, ArkBufferInfo info, uint32_t flag) = 0;
};

/*--web engine(source=library)--*/
class ArkMediaCodecDecoderAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkMediaCodecDecoderAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkMediaCodecDecoderAdapter() = default;

    /*--web engine()--*/
    virtual int32_t CreateVideoDecoderByMime(const ArkWebString& mimetype) = 0;

    /*--web engine()--*/
    virtual int32_t CreateVideoDecoderByName(const ArkWebString& name) = 0;

    /*--web engine()--*/
    virtual int32_t ConfigureDecoder(const ArkDecoderFormat& format) = 0;

    /*--web engine()--*/
    virtual int32_t SetParameterDecoder(const ArkDecoderFormat& format) = 0;

    /*--web engine()--*/
    virtual int32_t SetOutputSurface(void* window) = 0;

    /*--web engine()--*/
    virtual int32_t PrepareDecoder() = 0;

    /*--web engine()--*/
    virtual int32_t StartDecoder() = 0;

    /*--web engine()--*/
    virtual int32_t StopDecoder() = 0;

    /*--web engine()--*/
    virtual int32_t FlushDecoder() = 0;

    /*--web engine()--*/
    virtual int32_t ResetDecoder() = 0;

    /*--web engine()--*/
    virtual int32_t ReleaseDecoder() = 0;

    /*--web engine()--*/
    virtual int32_t QueueInputBufferDec(uint32_t index, ArkBufferInfo info, uint32_t flag) = 0;

    /*--web engine()--*/
    virtual int32_t GetOutputFormatDec(ArkDecoderFormat& format) = 0;

    /*--web engine()--*/
    virtual int32_t ReleaseOutputBufferDec(uint32_t index, bool isRender) = 0;

    /*--web engine()--*/
    virtual int32_t SetCallbackDec(const ArkWebRefPtr<ArkDecoderCallbackAdapter> callback) = 0;
};
} // namespace OHOS::ArkWeb

#endif // ARK_MEDIA_CODEC_DECODER_ADAPTER_H
