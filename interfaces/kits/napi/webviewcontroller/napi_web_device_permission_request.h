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

#ifndef NWEB_NAPI_WEB_DEVICE_PERMISSION_REQUEST_H
#define NWEB_NAPI_WEB_DEVICE_PERMISSION_REQUEST_H

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace NWeb {

// Napi wrapper for the WebDevicePermissionRequest class. This class only
// exposes the static Init() that registers the class on the module exports;
// instances are created by WebDevicePermissionDelegate::OnDevicePicker and
// have properties defined via DefineProperties.
class NapiWebDevicePermissionRequest {
public:
    static napi_value Init(napi_env env, napi_value exports);

    NapiWebDevicePermissionRequest() = default;
    ~NapiWebDevicePermissionRequest() = default;

    static napi_value JS_Constructor(napi_env env, napi_callback_info cbinfo);
    static napi_value JS_GetRequestInfo(napi_env env, napi_callback_info cbinfo);
    static napi_value JS_GetRequestId(napi_env env, napi_callback_info cbinfo);
    static napi_value JS_GetDeviceList(napi_env env, napi_callback_info cbinfo);
    static napi_value JS_Select(napi_env env, napi_callback_info cbinfo);
    static napi_value JS_Cancel(napi_env env, napi_callback_info cbinfo);
};

// Helper used by WebDevicePermissionDelegate::OnDevicePicker to attach the
// request methods onto a napi object that wraps a WebDevicePermissionRequest.
void NapiWebDevicePermissionRequest_DefineProperties(napi_env env, napi_value *obj);
} // namespace NWeb
} // namespace OHOS

#endif // NWEB_NAPI_WEB_DEVICE_PERMISSION_REQUEST_H
