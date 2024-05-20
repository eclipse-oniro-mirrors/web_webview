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

#ifndef ARK_CODEC_FORMAT_ADAPTER_IMPL_H
#define ARK_CODEC_FORMAT_ADAPTER_IMPL_H
#pragma once

#include "media_codec_adapter.h"
#include "ohos_adapter/include/ark_media_codec_adapter.h"

namespace OHOS::ArkWeb {

class ArkCodecFormatAdapterImpl : public ArkCodecFormatAdapter {
public:
    ArkCodecFormatAdapterImpl(std::shared_ptr<OHOS::NWeb::CodecFormatAdapter>);

    int32_t GetWidth() override;

    int32_t GetHeight() override;

private:
    std::shared_ptr<OHOS::NWeb::CodecFormatAdapter> real_;

    IMPLEMENT_REFCOUNTING(ArkCodecFormatAdapterImpl);
};

} // namespace OHOS::ArkWeb

#endif // ARK_CODEC_FORMAT_ADAPTER_IMPL_H
