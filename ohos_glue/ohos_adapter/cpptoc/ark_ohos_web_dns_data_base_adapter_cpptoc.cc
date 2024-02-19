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

#include "cpptoc/ark_ohos_web_dns_data_base_adapter_cpptoc.h"

#include "cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

bool ARK_WEB_CALLBACK ark_ohos_web_dns_data_base_adapter_exist_hostname(
    struct _ark_ohos_web_dns_data_base_adapter_t* self, const ArkWebString* hostname)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    ARK_WEB_CPPTOC_CHECK_PARAM(hostname, false);

    // Execute
    return ArkOhosWebDnsDataBaseAdapterCppToC::Get(self)->ExistHostname(*hostname);
}

void ARK_WEB_CALLBACK ark_ohos_web_dns_data_base_adapter_insert_hostname(
    struct _ark_ohos_web_dns_data_base_adapter_t* self, const ArkWebString* hostname)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    ARK_WEB_CPPTOC_CHECK_PARAM(hostname, );

    // Execute
    ArkOhosWebDnsDataBaseAdapterCppToC::Get(self)->InsertHostname(*hostname);
}

void ARK_WEB_CALLBACK ark_ohos_web_dns_data_base_adapter_get_hostnames(
    struct _ark_ohos_web_dns_data_base_adapter_t* self, ArkWebStringVector* hostnames)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    ARK_WEB_CPPTOC_CHECK_PARAM(hostnames, );

    // Execute
    ArkOhosWebDnsDataBaseAdapterCppToC::Get(self)->GetHostnames(*hostnames);
}

void ARK_WEB_CALLBACK ark_ohos_web_dns_data_base_adapter_clear_all_hostname(
    struct _ark_ohos_web_dns_data_base_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkOhosWebDnsDataBaseAdapterCppToC::Get(self)->ClearAllHostname();
}

} // namespace

ArkOhosWebDnsDataBaseAdapterCppToC::ArkOhosWebDnsDataBaseAdapterCppToC()
{
    GetStruct()->exist_hostname = ark_ohos_web_dns_data_base_adapter_exist_hostname;
    GetStruct()->insert_hostname = ark_ohos_web_dns_data_base_adapter_insert_hostname;
    GetStruct()->get_hostnames = ark_ohos_web_dns_data_base_adapter_get_hostnames;
    GetStruct()->clear_all_hostname = ark_ohos_web_dns_data_base_adapter_clear_all_hostname;
}

ArkOhosWebDnsDataBaseAdapterCppToC::~ArkOhosWebDnsDataBaseAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkOhosWebDnsDataBaseAdapterCppToC, ArkOhosWebDnsDataBaseAdapter,
    ark_ohos_web_dns_data_base_adapter_t>::kBridgeType = ARK_OHOS_WEB_DNS_DATA_BASE_ADAPTER;

} // namespace OHOS::ArkWeb
