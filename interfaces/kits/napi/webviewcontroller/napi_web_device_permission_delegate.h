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

#ifndef NWEB_NAPI_WEB_DEVICE_PERMISSION_DELEGATE_H
#define NWEB_NAPI_WEB_DEVICE_PERMISSION_DELEGATE_H

#include <memory>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"

#include "web_device_permission_delegate.h"

namespace OHOS {
namespace NWeb {

class NapiWebDevicePermissionDelegate {
public:
    static napi_value Init(napi_env env, napi_value exports);

    NapiWebDevicePermissionDelegate() = default;
    ~NapiWebDevicePermissionDelegate() = default;

    static napi_value JS_Constructor(napi_env env, napi_callback_info cbinfo);
    static napi_value JS_OnDevicePicker(napi_env env, napi_callback_info cbinfo);
    static napi_value JS_OnQueryDevicePermission(napi_env env, napi_callback_info cbinfo);
    static napi_value JS_OnPermissionRevoked(napi_env env, napi_callback_info cbinfo);
    static napi_value JS_OnDeviceListUpdated(napi_env env, napi_callback_info cbinfo);
};

// Wrapper that holds a shared_ptr<WebDevicePermissionDelegate> inside the
// napi wrapper. napi_wrap takes a raw void*, so we box the shared_ptr in
// this struct. The deleter decrements the shared_ptr refcount; the C++
// object is destroyed when the last shared_ptr copy is released (which may
// be the kernel's copy or this box's copy, whichever outlives the other).
// Exposed in the header so that NapiWebviewController::SetDevicePermissionDelegate
// can unwrap the JS delegate object and obtain the shared_ptr.
struct DelegateHolder {
    std::shared_ptr<WebDevicePermissionDelegate> delegate;
};
} // namespace NWeb
} // namespace OHOS

#endif // NWEB_NAPI_WEB_DEVICE_PERMISSION_DELEGATE_H
