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

#ifndef NWEB_WEB_DEVICE_PERMISSION_MANAGER_H
#define NWEB_WEB_DEVICE_PERMISSION_MANAGER_H

#include <map>
#include <memory>
#include <mutex>

#include "nweb_device_permission_delegate.h"

namespace OHOS {
namespace NWeb {

/**
 * @brief Manages device permission delegates by nweb id. Holds the delegates
 *        so they outlive the JS references that created them.
 */
class WebDevicePermissionManager {
public:
    static WebDevicePermissionManager& GetInstance();

    void SetDelegate(int32_t nwebId, std::shared_ptr<NWebDevicePermissionDelegate> delegate);

    std::shared_ptr<NWebDevicePermissionDelegate> GetDelegate(int32_t nwebId);

    void RemoveDelegate(int32_t nwebId);

private:
    WebDevicePermissionManager() = default;
    ~WebDevicePermissionManager() = default;
    WebDevicePermissionManager(const WebDevicePermissionManager&) = delete;
    WebDevicePermissionManager& operator=(const WebDevicePermissionManager&) = delete;

    std::mutex mutex_;
    std::map<int32_t, std::shared_ptr<NWebDevicePermissionDelegate>> delegates_;
};
} // namespace NWeb
} // namespace OHOS

#endif // NWEB_WEB_DEVICE_PERMISSION_MANAGER_H
