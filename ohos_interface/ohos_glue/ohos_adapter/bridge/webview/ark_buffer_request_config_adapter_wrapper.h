/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef ARK_BUFFER_REQUEST_CONFIG_ADAPTER_WRAPPER_H
#define ARK_BUFFER_REQUEST_CONFIG_ADAPTER_WRAPPER_H
#pragma once

#include "graphic_adapter.h"
#include "ohos_adapter/include/ark_graphic_adapter.h"

namespace OHOS::ArkWeb {

class ArkBufferRequestConfigAdapterWrapper : public NWeb::BufferRequestConfigAdapter {
public:
    ArkBufferRequestConfigAdapterWrapper(ArkWebRefPtr<ArkBufferRequestConfigAdapter>);

    int32_t GetWidth() override;

    int32_t GetHeight() override;

    int32_t GetStrideAlignment() override;

    int32_t GetFormat() override;

    uint64_t GetUsage() override;

    int32_t GetTimeout() override;

    NWeb::ColorGamutAdapter GetColorGamut() override;

    NWeb::TransformTypeAdapter GetTransformType() override;

private:
    ArkWebRefPtr<ArkBufferRequestConfigAdapter> ctocpp_;
};

} // namespace OHOS::ArkWeb

#endif // ARK_BUFFER_REQUEST_CONFIG_ADAPTER_WRAPPER_H
