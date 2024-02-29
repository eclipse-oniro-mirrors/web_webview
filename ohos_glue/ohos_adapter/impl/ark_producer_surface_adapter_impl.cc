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

#include "ark_producer_surface_adapter_impl.h"

#include "ark_surface_buffer_adapter_impl.h"
#include "bridge/ark_web_bridge_macros.h"

namespace OHOS::ArkWeb {

ArkProducerSurfaceAdapterImpl::ArkProducerSurfaceAdapterImpl(std::shared_ptr<OHOS::NWeb::ProducerSurfaceAdapter> ref)
    : real_(ref)
{}

ArkWebRefPtr<ArkSurfaceBufferAdapter> ArkProducerSurfaceAdapterImpl::RequestBuffer
    (int32_t &fence, ArkBufferRequestConfigAdapter &config)
{
    std::shared_ptr<OHOS::NWeb::SurfaceBufferAdapter> buffer = real_->RequestBuffer(fence, config);
    if (CHECK_SHARED_PTR_IS_NULL(buffer)) {
        return nullptr;
    }

    return new ArkSurfaceBufferAdapterImpl(buffer);
}

int32_t ArkProducerSurfaceAdapterImpl::FlushBuffer(ArkWebRefPtr<ArkSurfaceBufferAdapter> buffer,
                        int32_t fence, ArkBufferFlushConfigAdapter &flushConfig)
{
    ArkSurfaceBufferAdapterImpl* imp = static_cast<ArkSurfaceBufferAdapterImpl*>(buffer.get());
    return real_->FlushBuffer(std::move(imp->real_), fence, flushConfig);
}

} // namespace OHOS::ArkWeb
