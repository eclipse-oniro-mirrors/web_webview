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

#include "ark_system_properties_adapter_impl.h"

namespace OHOS::ArkWeb {

ArkSystemPropertiesAdapterImpl::ArkSystemPropertiesAdapterImpl(NWeb::SystemPropertiesAdapter& ref) : real_(ref) {}

bool ArkSystemPropertiesAdapterImpl::GetResourceUseHapPathEnable()
{
    return real_.GetResourceUseHapPathEnable();
}

ArkWebString ArkSystemPropertiesAdapterImpl::GetDeviceInfoProductModel()
{
    std::string str = real_.GetDeviceInfoProductModel();
    return ArkWebStringClassToStruct(str);
}

ArkWebString ArkSystemPropertiesAdapterImpl::GetDeviceInfoBrand()
{
    std::string str = real_.GetDeviceInfoBrand();
    return ArkWebStringClassToStruct(str);
}

int32_t ArkSystemPropertiesAdapterImpl::GetDeviceInfoMajorVersion()
{
    return real_.GetDeviceInfoMajorVersion();
}

int32_t ArkSystemPropertiesAdapterImpl::GetProductDeviceType()
{
    return (int32_t)real_.GetProductDeviceType();
}

bool ArkSystemPropertiesAdapterImpl::GetWebOptimizationValue()
{
    return real_.GetWebOptimizationValue();
}

bool ArkSystemPropertiesAdapterImpl::GetLockdownModeStatus()
{
    return real_.GetLockdownModeStatus();
}

ArkWebString ArkSystemPropertiesAdapterImpl::GetUserAgentOSName()
{
    std::string str = real_.GetUserAgentOSName();
    return ArkWebStringClassToStruct(str);
}

int32_t ArkSystemPropertiesAdapterImpl::GetSoftwareMajorVersion()
{
    return real_.GetSoftwareMajorVersion();
}

int32_t ArkSystemPropertiesAdapterImpl::GetSoftwareSeniorVersion()
{
    return real_.GetSoftwareSeniorVersion();
}

ArkWebString ArkSystemPropertiesAdapterImpl::GetNetlogMode()
{
    std::string str = real_.GetNetlogMode();
    return ArkWebStringClassToStruct(str);
}

bool ArkSystemPropertiesAdapterImpl::GetTraceDebugEnable()
{
    return real_.GetTraceDebugEnable();
}

} // namespace OHOS::ArkWeb