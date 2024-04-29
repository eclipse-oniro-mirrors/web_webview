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

#ifndef ARK_PRODUCER_SURFACE_ADAPTER_IMPL_H
#define ARK_PRODUCER_SURFACE_ADAPTER_IMPL_H
#pragma once

#include "graphic_adapter.h"
#include "ohos_adapter/include/ark_graphic_adapter.h"

namespace OHOS::ArkWeb {

class ArkProducerSurfaceAdapterImpl : public ArkProducerSurfaceAdapter {
public:
    ArkProducerSurfaceAdapterImpl(std::shared_ptr<OHOS::NWeb::ProducerSurfaceAdapter>);

    ArkWebRefPtr<ArkSurfaceBufferAdapter> RequestBuffer(
        int32_t& fence, ArkWebRefPtr<ArkBufferRequestConfigAdapter> config) override;

    int32_t FlushBuffer(ArkWebRefPtr<ArkSurfaceBufferAdapter> buffer, int32_t fence,
        ArkWebRefPtr<ArkBufferFlushConfigAdapter> flushConfig) override;

    std::shared_ptr<OHOS::NWeb::ProducerSurfaceAdapter> real_;

    IMPLEMENT_REFCOUNTING(ArkProducerSurfaceAdapterImpl);
};

} // namespace OHOS::ArkWeb

#endif // ARK_PRODUCER_SURFACE_ADAPTER_IMPL_H
