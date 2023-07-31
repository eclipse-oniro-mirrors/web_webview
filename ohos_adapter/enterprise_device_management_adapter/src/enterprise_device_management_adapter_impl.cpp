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

#include "enterprise_device_management_adapter_impl.h"

#include "nweb_log.h"
#include "browser_proxy.h"

namespace OHOS::NWeb {
using namespace OHOS::EDM;

// static
EnterpriseDeviceManagementAdapterImpl& EnterpriseDeviceManagementAdapterImpl::GetInstance()
{
    static EnterpriseDeviceManagementAdapterImpl instance;
    return instance;
}

int32_t EnterpriseDeviceManagementAdapterImpl::GetPolicies(std::string& policies)
{
    auto proxy = BrowserProxy::GetBrowserProxy();
    if (!proxy) {
        WVLOG_E("EnterpriseDeviceManagementAdapterImpl BrowserProxy is null");
        return -1;
    }
    return proxy->GetPolicies(policies);
}

} // namespace OHOS::NWeb