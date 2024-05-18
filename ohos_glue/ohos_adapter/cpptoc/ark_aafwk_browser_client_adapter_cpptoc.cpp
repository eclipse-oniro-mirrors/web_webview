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

#include "ohos_adapter/cpptoc/ark_aafwk_browser_client_adapter_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb{

namespace{

void* ARK_WEB_CALLBACK ark_aafwk_browser_client_adapter_query_render_surface(
    struct _ark_aafwk_browser_client_adapter_t* self, int32_t surface_id)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkAafwkBrowserClientAdapterCppToC::Get(self)->QueryRenderSurface(surface_id);
}

void ARK_WEB_CALLBACK ark_aafwk_browser_client_adapter_report_thread(
    struct _ark_aafwk_browser_client_adapter_t* self, int32_t status,
    int32_t process_id, int32_t thread_id, int32_t role)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    return ArkAafwkBrowserClientAdapterCppToC::Get(self)->ReportThread(status, process_id, thread_id, role);
}

void ARK_WEB_CALLBACK ark_aafwk_browser_client_adapter_pass_surface(
    struct _ark_aafwk_browser_client_adapter_t* self, int64_t surface_id)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    return ArkAafwkBrowserClientAdapterCppToC::Get(self)->PassSurface(surface_id);
}

void ARK_WEB_CALLBACK ark_aafwk_browser_client_adapter_destroy_render_surface(
    struct _ark_aafwk_browser_client_adapter_t* self, int32_t surface_id)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    return ArkAafwkBrowserClientAdapterCppToC::Get(self)->DestroyRenderSurface(surface_id);
}
} // namespace

ArkAafwkBrowserClientAdapterCppToC::ArkAafwkBrowserClientAdapterCppToC()
{
    GetStruct()->query_render_surface = ark_aafwk_browser_client_adapter_query_render_surface;
    GetStruct()->report_thread = ark_aafwk_browser_client_adapter_report_thread;
    GetStruct()->pass_surface = ark_aafwk_browser_client_adapter_pass_surface;
    GetStruct()->destroy_render_surface = ark_aafwk_browser_client_adapter_destroy_render_surface;
}

ArkAafwkBrowserClientAdapterCppToC::~ArkAafwkBrowserClientAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkAafwkBrowserClientAdapterCppToC,
    ArkAafwkBrowserClientAdapter,
    ark_aafwk_browser_client_adapter_t>::kBridgeType = ARK_AAFWK_BROWSER_CLIENT_ADAPTER;

} // namespace OHOS::ArkWeb