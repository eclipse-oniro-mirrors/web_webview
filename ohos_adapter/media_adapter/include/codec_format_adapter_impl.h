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

#ifndef CODEC_FORMAT_ADAPTER_IMPL_H
#define CODEC_FORMAT_ADAPTER_IMPL_H

#include "media_codec_adapter.h"

namespace OHOS::NWeb {

class CodecFormatAdapterImpl : public CodecFormatAdapter {
public:
    CodecFormatAdapterImpl() = default;

    int32_t GetWidth() override;

    int32_t GetHeight() override;

    void SetWidth(int32_t width);

    void SetHeight(int32_t height);

private:
    int32_t width_ = 0;
    int32_t height_ = 0;
};

} // namespace OHOS::NWeb

#endif // CODEC_FORMAT_ADAPTER_IMPL_H
