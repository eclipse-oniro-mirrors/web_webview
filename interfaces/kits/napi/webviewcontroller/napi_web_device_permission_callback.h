/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef NAPI_WEB_DEVICE_PERMISSION_CALLBACK_H
#define NAPI_WEB_DEVICE_PERMISSION_CALLBACK_H

#include <memory>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "nweb_device_permission_delegate.h"

namespace OHOS {
namespace NWeb {

// Creates a JS object that wraps an NWebPermissionOriginsResultCallback.
// The application calls obj.reply(config: Array<WebDevicePermissionConfig>)
// or obj.cancel().
class NapiWebPermissionOriginsResultCallback {
public:
    static napi_value Create(napi_env env, std::shared_ptr<NWebPermissionOriginsResultCallback> callback);
};

// Helper functions to build JS objects from NWeb structs. Used by
// WebDevicePermissionDelegate to construct the arguments passed to the
// application's onPermissionRevoked / etc. callbacks.
napi_value NapiWebDevicePermissionCallback_CreateDeviceIdentifier(
    napi_env env, const NWebDevicePermissionDeviceIdentifier& device);

napi_value NapiWebDevicePermissionCallback_CreateRevokedEvent(
    napi_env env, const NWebDevicePermissionRevokedEvent& event);

napi_value NapiWebDevicePermissionCallback_CreateDeviceListUpdateEvent(
    napi_env env, const NWebDeviceListUpdateEvent& event);

} // namespace NWeb
} // namespace OHOS

#endif // NAPI_WEB_DEVICE_PERMISSION_CALLBACK_H
