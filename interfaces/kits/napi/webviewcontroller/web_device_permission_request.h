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

#ifndef NWEB_WEB_DEVICE_PERMISSION_REQUEST_H
#define NWEB_WEB_DEVICE_PERMISSION_REQUEST_H

#include <memory>
#include <string>
#include <vector>

#include "napi/native_api.h"
#include "nweb_device_permission_delegate.h"

namespace OHOS {
namespace NWeb {

class WebDevicePermissionRequestHolder {
public:
    WebDevicePermissionRequestHolder() = default;
    ~WebDevicePermissionRequestHolder() = default;

    int32_t nwebId_ = -1;
    std::string requestId_;
    NWebDevicePermissionRequestBase requestInfo_;
    std::vector<NWebDevicePermissionDeviceIdentifier> devices_;
    std::shared_ptr<NWebDevicePermissionResultCallback> callback_;
};

class NapiWebDevicePermissionRequest {
public:
    NapiWebDevicePermissionRequest() = default;
    ~NapiWebDevicePermissionRequest() = default;

    static napi_value JsConstructor(napi_env env, napi_callback_info info);
    static napi_value GetRequestInfo(napi_env env, napi_callback_info info);
    static napi_value GetRequestId(napi_env env, napi_callback_info info);
    static napi_value GetDeviceList(napi_env env, napi_callback_info info);
    static napi_value Select(napi_env env, napi_callback_info info);
    static napi_value Cancel(napi_env env, napi_callback_info info);

    static napi_value Init(napi_env env, napi_value exports);

    static napi_value CreateInstance(napi_env env, int32_t nwebId, const std::string& requestId,
        const NWebDevicePermissionRequestBase& requestInfo,
        const std::vector<NWebDevicePermissionDeviceIdentifier>& devices,
        std::shared_ptr<NWebDevicePermissionResultCallback> callback);
};
} // namespace NWeb
} // namespace OHOS

#endif // NWEB_WEB_DEVICE_PERMISSION_REQUEST_H
