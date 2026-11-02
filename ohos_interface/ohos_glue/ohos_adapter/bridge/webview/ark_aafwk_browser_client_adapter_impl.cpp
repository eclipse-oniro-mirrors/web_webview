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

#include "ark_aafwk_browser_client_adapter_impl.h"

#include "base/bridge/ark_web_bridge_macros.h"
#include "base/include/ark_web_log_utils.h"

namespace OHOS::ArkWeb {
ArkAafwkBrowserClientAdapterImpl::ArkAafwkBrowserClientAdapterImpl(
    std::shared_ptr<OHOS::NWeb::AafwkBrowserClientAdapter> ref)
    : real_(ref)
{}

void* ArkAafwkBrowserClientAdapterImpl::QueryRenderSurface(int32_t surface_id)
{
    if (CHECK_SHARED_PTR_IS_NULL(real_)) {
        WVLOG_E("ArkAafwkBrowserClientAdapterImpl::QueryRenderSurface, real_ is null.");
        return nullptr;
    }
    return real_->QueryRenderSurface(surface_id);
}

void ArkAafwkBrowserClientAdapterImpl::ReportThread(int32_t status, int32_t process_id, int32_t thread_id, int32_t role)
{
    if (CHECK_SHARED_PTR_IS_NULL(real_)) {
        WVLOG_E("ArkAafwkBrowserClientAdapterImpl::ReportThread, real_ is null.");
        return;
    }
    real_->ReportThread((NWeb::ResSchedStatusAdapter)status, process_id, thread_id, (NWeb::ResSchedRoleAdapter)role);
}

void ArkAafwkBrowserClientAdapterImpl::PassSurface(int64_t surface_id)
{
    if (CHECK_SHARED_PTR_IS_NULL(real_)) {
        WVLOG_E("ArkAafwkBrowserClientAdapterImpl::PassSurface, real_ is null.");
        return;
    }
    real_->PassSurface(surface_id);
}

void ArkAafwkBrowserClientAdapterImpl::DestroyRenderSurface(int32_t surface_id)
{
    if (CHECK_SHARED_PTR_IS_NULL(real_)) {
        WVLOG_E("ArkAafwkBrowserClientAdapterImpl::DestroyRenderSurface, real_ is null.");
        return;
    }
    return real_->DestroyRenderSurface(surface_id);
}

ArkWebString ArkAafwkBrowserClientAdapterImpl::QueryBufferTypeLeak(int32_t surface_id)
{
    if (CHECK_SHARED_PTR_IS_NULL(real_)) {
        WVLOG_E("ArkAafwkBrowserClientAdapterImpl::QueryBufferTypeLeak, real_ is null.");
        return ark_web_string_default;
    }
    return ArkWebStringClassToStruct(real_->QueryBufferTypeLeak(surface_id));
}

} // namespace OHOS::ArkWeb