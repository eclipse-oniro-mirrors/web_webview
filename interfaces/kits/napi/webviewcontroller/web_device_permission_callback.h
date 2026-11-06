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

#ifndef NWEB_WEB_DEVICE_PERMISSION_CALLBACK_H
#define NWEB_WEB_DEVICE_PERMISSION_CALLBACK_H

#include <memory>

#include "napi/native_api.h"
#include "nweb_device_permission_delegate.h"

namespace OHOS {
namespace NWeb {

class WebDevicePermissionEventHolder {
public:
    WebDevicePermissionEventHolder() = default;
    ~WebDevicePermissionEventHolder() = default;

    std::shared_ptr<NWebPermissionOriginsResultCallback> callback_;
};

/**
 * @brief Create a js event object with a reply(config) method. The method
 *        forwards the configuration to the engine through the result callback.
 */
napi_value CreateDevicePermissionEventJsObject(napi_env env,
    std::shared_ptr<NWebPermissionOriginsResultCallback> callback);
} // namespace NWeb
} // namespace OHOS

#endif // NWEB_WEB_DEVICE_PERMISSION_CALLBACK_H
