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

#include "ark_location_instance_impl.h"

#include "ark_location_proxy_adapter_impl.h"
#include "ark_location_request_config_impl.h"

namespace OHOS::ArkWeb {

ArkWebRefPtr<ArkLocationInstance> ArkLocationInstance::GetInstance()
{
    static NWeb::LocationInstance& instance = NWeb::LocationInstance::GetInstance();
    static ArkLocationInstanceImpl impl(instance);
    return &impl;
}

ArkLocationInstanceImpl::ArkLocationInstanceImpl(NWeb::LocationInstance& ref) : real_(ref) {}

ArkWebRefPtr<ArkLocationProxyAdapter> ArkLocationInstanceImpl::CreateLocationProxyAdapter()
{
    return new ArkLocationProxyAdapterImpl(real_.CreateLocationProxyAdapter());
}

ArkWebRefPtr<ArkLocationRequestConfig> ArkLocationInstanceImpl::CreateLocationRequestConfig()
{
    return new ArkLocationRequestConfigImpl(real_.CreateLocationRequestConfig());
}

} // namespace OHOS::ArkWeb
