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

#include "location_proxy_adapter_impl.h"

#include <string>

namespace OHOS::NWeb {
LocationInstance& LocationInstance::GetInstance()
{
    static LocationInstance instance;
    return instance;
}

std::unique_ptr<LocationProxyAdapter> LocationInstance::CreateLocationProxyAdapter()
{
    return nullptr;
}

std::unique_ptr<LocationRequestConfig> LocationInstance::CreateLocationRequestConfig()
{
    return nullptr;
}

LocationRequestConfigImpl::LocationRequestConfigImpl() {}

void LocationRequestConfigImpl::SetScenario(int32_t scenario) {}

void LocationRequestConfigImpl::SetFixNumber(int32_t number) {}

void LocationRequestConfigImpl::SetMaxAccuracy(int32_t maxAccuary) {}

void LocationRequestConfigImpl::SetDistanceInterval(int32_t disInterval) {}

void LocationRequestConfigImpl::SetTimeInterval(int32_t timeInterval) {}

void LocationRequestConfigImpl::SetPriority(int32_t priority) {}

double LocationInfoImpl::GetLatitude() const
{
    return -1;
}

double LocationInfoImpl::GetLongitude() const
{
    return -1;
}

double LocationInfoImpl::GetAltitude() const
{
    return -1;
}

float LocationInfoImpl::GetAccuracy() const
{
    return -1;
}

float LocationInfoImpl::GetSpeed() const
{
    return -1;
}

double LocationInfoImpl::GetDirection() const
{
    return -1;
}

int64_t LocationInfoImpl::GetTimeStamp() const
{
    return -1;
}

int64_t LocationInfoImpl::GetTimeSinceBoot() const
{
    return -1;
}

std::string LocationInfoImpl::GetAdditions() const
{
    return std::string();
}

LocationProxyAdapterImpl::LocationProxyAdapterImpl() {}

bool LocationProxyAdapterImpl::StartLocating(
    std::unique_ptr<LocationRequestConfig>& requestConfig, std::shared_ptr<LocationCallbackAdapter> callback)
{
    return false;
}

bool LocationProxyAdapterImpl::StopLocating(std::shared_ptr<LocationCallbackAdapter> callback)
{
    return false;
}

bool LocationProxyAdapterImpl::EnableAbility(bool isEnabled)
{
    return false;
}

bool LocationProxyAdapterImpl::IsLocationEnabled()
{
    return false;
}
} // namespace OHOS::NWeb
