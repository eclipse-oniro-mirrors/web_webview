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

#ifndef ARK_MEDIA_CODEC_ENCODER_ADAPTER_H
#define ARK_MEDIA_CODEC_ENCODER_ADAPTER_H

#pragma once

#include <cstdint>

#include "ark_graphic_adapter.h"
#include "include/ark_web_base_ref_counted.h"
#include "include/ark_web_types.h"
#include "media_codec_adapter.h"

using ArkCodecFormatAdapter = OHOS::NWeb::CodecFormatAdapter;
using ArkBufferInfo = OHOS::NWeb::BufferInfo;
using ArkOhosBuffer = OHOS::NWeb::OhosBuffer;
using ArkCodecConfigPara = OHOS::NWeb::CodecConfigPara;
using ArkCapabilityDataAdapter = OHOS::NWeb::CapabilityDataAdapter;

namespace OHOS::ArkWeb {

/*--web engine(source=client)--*/
class ArkCodecCallbackAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkCodecCallbackAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkCodecCallbackAdapter() = default;

    /*--web engine()--*/
    virtual void OnError(int32_t errorType, int32_t errorCode) = 0;

    /*--web engine()--*/
    virtual void OnStreamChanged(const ArkCodecFormatAdapter& format) = 0;

    /*--web engine()--*/
    virtual void OnNeedInputData(uint32_t index, ArkOhosBuffer buffer) = 0;

    /*--web engine()--*/
    virtual void OnNeedOutputData(uint32_t index, ArkBufferInfo info, int32_t flag, ArkOhosBuffer buffer) = 0;
};

/*--web engine(source=library)--*/
class ArkMediaCodecAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkMediaCodecAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkMediaCodecAdapter() = default;

    /*--web engine()--*/
    virtual int32_t CreateVideoCodecByMime(const ArkWebString mimetype) = 0;

    /*--web engine()--*/
    virtual int32_t CreateVideoCodecByName(const ArkWebString name) = 0;

    /*--web engine()--*/
    virtual int32_t SetCodecCallback(const ArkWebRefPtr<ArkCodecCallbackAdapter> callback) = 0;

    /*--web engine()--*/
    virtual int32_t Configure(const ArkCodecConfigPara& config) = 0;

    /*--web engine()--*/
    virtual int32_t Prepare() = 0;

    /*--web engine()--*/
    virtual int32_t Start() = 0;

    /*--web engine()--*/
    virtual int32_t Stop() = 0;

    /*--web engine()--*/
    virtual int32_t Reset() = 0;

    /*--web engine()--*/
    virtual int32_t Release() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkProducerSurfaceAdapter> CreateInputSurface() = 0;

    /*--web engine()--*/
    virtual int32_t ReleaseOutputBuffer(uint32_t index, bool isRender) = 0;

    /*--web engine()--*/
    virtual int32_t RequestKeyFrameSoon() = 0;
};

/*--web engine(source=library)--*/
class ArkMediaCodecListAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkMediaCodecListAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkMediaCodecListAdapter() = default;

    /*--web engine()--*/
    virtual ArkCapabilityDataAdapter GetCodecCapability(const ArkWebString mime, const bool isCodec) = 0;
};
} // namespace OHOS::ArkWeb

#endif // ARK_MEDIA_CODEC_ENCODER_ADAPTER_H
