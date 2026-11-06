/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "web_device_permission_manager.h"

namespace OHOS {
namespace NWeb {

WebDevicePermissionManager& WebDevicePermissionManager::GetInstance()
{
    static WebDevicePermissionManager instance;
    return instance;
}

void WebDevicePermissionManager::SetDelegate(int32_t nwebId,
    std::shared_ptr<NWebDevicePermissionDelegate> delegate)
{
    std::lock_guard<std::mutex> lock(mutex_);
    delegates_[nwebId] = delegate;
}

std::shared_ptr<NWebDevicePermissionDelegate> WebDevicePermissionManager::GetDelegate(int32_t nwebId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = delegates_.find(nwebId);
    if (it == delegates_.end()) {
        return nullptr;
    }
    return it->second;
}

void WebDevicePermissionManager::RemoveDelegate(int32_t nwebId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    delegates_.erase(nwebId);
}
} // namespace NWeb
} // namespace OHOS
