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

#ifndef overrideARK_MEDIA_CODEC_ENCODER_ADAPTER_WRAPPER_H
#define overrideARK_MEDIA_CODEC_ENCODER_ADAPTER_WRAPPER_H
#pragma once

#include "media_codec_adapter.h"
#include "ohos_adapter/include/ark_media_codec_adapter.h"

namespace OHOS::ArkWeb {

class ArkMediaCodecEncoderAdapterWrapper : public OHOS::NWeb::MediaCodecAdapter {
public:
    ArkMediaCodecEncoderAdapterWrapper(ArkWebRefPtr<ArkMediaCodecAdapter>);

    OHOS::NWeb::CodecCodeAdapter CreateVideoCodecByMime(const std::string mimetype) override;

    OHOS::NWeb::CodecCodeAdapter CreateVideoCodecByName(const std::string name) override;

    OHOS::NWeb::CodecCodeAdapter SetCodecCallback(
        const std::shared_ptr<OHOS::NWeb::CodecCallbackAdapter> callback) override;

    OHOS::NWeb::CodecCodeAdapter Configure(const std::shared_ptr<OHOS::NWeb::CodecConfigParaAdapter> config) override;

    OHOS::NWeb::CodecCodeAdapter Prepare() override;

    OHOS::NWeb::CodecCodeAdapter Start() override;

    OHOS::NWeb::CodecCodeAdapter Stop() override;

    OHOS::NWeb::CodecCodeAdapter Reset() override;

    OHOS::NWeb::CodecCodeAdapter Release() override;

    std::shared_ptr<OHOS::NWeb::ProducerSurfaceAdapter> CreateInputSurface() override;

    OHOS::NWeb::CodecCodeAdapter ReleaseOutputBuffer(uint32_t index, bool isRender) override;

    OHOS::NWeb::CodecCodeAdapter RequestKeyFrameSoon() override;

private:
    ArkWebRefPtr<ArkMediaCodecAdapter> ctocpp_;
};

} // namespace OHOS::ArkWeb

#endif // overrideARK_MEDIA_CODEC_ENCODER_ADAPTER_WRAPPER_H
