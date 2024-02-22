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

#ifndef ARK_MEDIA_CODEC_DECODER_ADAPTER_IMPL_H
#define ARK_MEDIA_CODEC_DECODER_ADAPTER_IMPL_H

#pragma once

#include "include/ark_media_codec_decoder_adapter.h"
#include "media_codec_decoder_adapter.h"

namespace OHOS::ArkWeb {

class ArkMediaCodecDecoderAdapterImpl : public ArkMediaCodecDecoderAdapter {
public:
    ArkMediaCodecDecoderAdapterImpl(std::shared_ptr<OHOS::NWeb::MediaCodecDecoderAdapter>);

    int32_t CreateVideoDecoderByMime(const ArkWebString& mimetype) override;

    int32_t CreateVideoDecoderByName(const ArkWebString& name) override;

    int32_t ConfigureDecoder(const ArkDecoderFormat& format) override;

    int32_t SetParameterDecoder(const ArkDecoderFormat& format) override;

    int32_t SetOutputSurface(void* window) override;

    int32_t PrepareDecoder() override;

    int32_t StartDecoder() override;

    int32_t StopDecoder() override;

    int32_t FlushDecoder() override;

    int32_t ResetDecoder() override;

    int32_t ReleaseDecoder() override;

    int32_t QueueInputBufferDec(uint32_t index, ArkBufferInfo info, uint32_t flag) override;

    int32_t GetOutputFormatDec(ArkDecoderFormat& format) override;

    int32_t ReleaseOutputBufferDec(uint32_t index, bool isRender) override;

    int32_t SetCallbackDec(const ArkWebRefPtr<ArkDecoderCallbackAdapter> callback) override;

private:
    std::shared_ptr<OHOS::NWeb::MediaCodecDecoderAdapter> real_;

    IMPLEMENT_REFCOUNTING(ArkMediaCodecDecoderAdapterImpl);
};
} // namespace OHOS::ArkWeb

#endif // ARK_MEDIA_CODEC_DECODER_ADAPTER_IMPL_H
