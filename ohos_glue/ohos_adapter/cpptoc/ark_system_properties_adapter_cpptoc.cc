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

#include "cpptoc/ark_system_properties_adapter_cpptoc.h"

#include "cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

bool ARK_WEB_CALLBACK ark_system_properties_adapter_get_resource_use_hap_path_enable(
    struct _ark_system_properties_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkSystemPropertiesAdapterCppToC::Get(self)->GetResourceUseHapPathEnable();
}

ArkWebString ARK_WEB_CALLBACK ark_system_properties_adapter_get_device_info_product_model(
    struct _ark_system_properties_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_string_default);

    // Execute
    return ArkSystemPropertiesAdapterCppToC::Get(self)->GetDeviceInfoProductModel();
}

ArkWebString ARK_WEB_CALLBACK ark_system_properties_adapter_get_device_info_brand(
    struct _ark_system_properties_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_string_default);

    // Execute
    return ArkSystemPropertiesAdapterCppToC::Get(self)->GetDeviceInfoBrand();
}

int32_t ARK_WEB_CALLBACK ark_system_properties_adapter_get_device_info_major_version(
    struct _ark_system_properties_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkSystemPropertiesAdapterCppToC::Get(self)->GetDeviceInfoMajorVersion();
}

int32_t ARK_WEB_CALLBACK ark_system_properties_adapter_get_product_device_type(
    struct _ark_system_properties_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkSystemPropertiesAdapterCppToC::Get(self)->GetProductDeviceType();
}

bool ARK_WEB_CALLBACK ark_system_properties_adapter_get_web_optimization_value(
    struct _ark_system_properties_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkSystemPropertiesAdapterCppToC::Get(self)->GetWebOptimizationValue();
}

bool ARK_WEB_CALLBACK ark_system_properties_adapter_get_lockdown_mode_status(
    struct _ark_system_properties_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkSystemPropertiesAdapterCppToC::Get(self)->GetLockdownModeStatus();
}

ArkWebString ARK_WEB_CALLBACK ark_system_properties_adapter_get_user_agent_osname(
    struct _ark_system_properties_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_string_default);

    // Execute
    return ArkSystemPropertiesAdapterCppToC::Get(self)->GetUserAgentOSName();
}

int32_t ARK_WEB_CALLBACK ark_system_properties_adapter_get_software_major_version(
    struct _ark_system_properties_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkSystemPropertiesAdapterCppToC::Get(self)->GetSoftwareMajorVersion();
}

int32_t ARK_WEB_CALLBACK ark_system_properties_adapter_get_software_senior_version(
    struct _ark_system_properties_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkSystemPropertiesAdapterCppToC::Get(self)->GetSoftwareSeniorVersion();
}

ArkWebString ARK_WEB_CALLBACK ark_system_properties_adapter_get_netlog_mode(
    struct _ark_system_properties_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_string_default);

    // Execute
    return ArkSystemPropertiesAdapterCppToC::Get(self)->GetNetlogMode();
}

bool ARK_WEB_CALLBACK ark_system_properties_adapter_get_trace_debug_enable(
    struct _ark_system_properties_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkSystemPropertiesAdapterCppToC::Get(self)->GetTraceDebugEnable();
}

} // namespace

ArkSystemPropertiesAdapterCppToC::ArkSystemPropertiesAdapterCppToC()
{
    GetStruct()->get_resource_use_hap_path_enable = ark_system_properties_adapter_get_resource_use_hap_path_enable;
    GetStruct()->get_device_info_product_model = ark_system_properties_adapter_get_device_info_product_model;
    GetStruct()->get_device_info_brand = ark_system_properties_adapter_get_device_info_brand;
    GetStruct()->get_device_info_major_version = ark_system_properties_adapter_get_device_info_major_version;
    GetStruct()->get_product_device_type = ark_system_properties_adapter_get_product_device_type;
    GetStruct()->get_web_optimization_value = ark_system_properties_adapter_get_web_optimization_value;
    GetStruct()->get_lockdown_mode_status = ark_system_properties_adapter_get_lockdown_mode_status;
    GetStruct()->get_user_agent_osname = ark_system_properties_adapter_get_user_agent_osname;
    GetStruct()->get_software_major_version = ark_system_properties_adapter_get_software_major_version;
    GetStruct()->get_software_senior_version = ark_system_properties_adapter_get_software_senior_version;
    GetStruct()->get_netlog_mode = ark_system_properties_adapter_get_netlog_mode;
    GetStruct()->get_trace_debug_enable = ark_system_properties_adapter_get_trace_debug_enable;
}

ArkSystemPropertiesAdapterCppToC::~ArkSystemPropertiesAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkSystemPropertiesAdapterCppToC, ArkSystemPropertiesAdapter,
    ark_system_properties_adapter_t>::kBridgeType = ARK_SYSTEM_PROPERTIES_ADAPTER;

} // namespace OHOS::ArkWeb