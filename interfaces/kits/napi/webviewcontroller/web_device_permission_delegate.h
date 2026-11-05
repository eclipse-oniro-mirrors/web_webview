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

#ifndef NWEB_WEB_DEVICE_PERMISSION_DELEGATE_H
#define NWEB_WEB_DEVICE_PERMISSION_DELEGATE_H

#include <memory>
#include <string>
#include <vector>

#include "napi/native_api.h"
#include "nweb_device_permission_delegate.h"

namespace OHOS {
namespace NWeb {

class WebDevicePermissionDelegate;

/**
 * @brief Holder for napi_wrap/unwrap. Owns the shared_ptr of the delegate so
 *        the delegate outlives the JS object that wraps it.
 */
class WebDevicePermissionDelegateHolder {
public:
    WebDevicePermissionDelegateHolder() = default;
    ~WebDevicePermissionDelegateHolder() = default;

    std::shared_ptr<WebDevicePermissionDelegate> delegate_;
};

class WebDevicePermissionDelegate : public NWebDevicePermissionDelegate {
public:
    explicit WebDevicePermissionDelegate(napi_env env);
    ~WebDevicePermissionDelegate() override;

    void OnQueryDevicePermissionOrigins(int32_t nweb_id,
        std::shared_ptr<NWebPermissionOriginsResultCallback> callback) override;

    void OnPermissionRevoked(int32_t nweb_id,
        const NWebDevicePermissionRevokedEvent& event) override;

    void OnDevicePicker(int32_t nweb_id, const std::string& request_id,
        const NWebDevicePermissionRequestBase& request_info,
        const std::vector<NWebDevicePermissionDeviceIdentifier>& devices,
        std::shared_ptr<NWebDevicePermissionResultCallback> callback) override;

    void OnDeviceListUpdated(int32_t nweb_id,
        const NWebDeviceListUpdateEvent& event) override;

    void PutOnQueryDevicePermission(napi_env env, napi_value callback);
    void PutOnPermissionRevoked(napi_env env, napi_value callback);
    void PutOnDevicePicker(napi_env env, napi_value callback);
    void PutOnDeviceListUpdated(napi_env env, napi_value callback);

    napi_env GetEnv()
    {
        return env_;
    }

private:
    napi_env env_ = nullptr;
    napi_ref on_query_permission_callback_ = nullptr;
    napi_ref on_permission_revoked_callback_ = nullptr;
    napi_ref on_device_picker_callback_ = nullptr;
    napi_ref on_device_list_updated_callback_ = nullptr;
};

class NapiWebDevicePermissionDelegate {
public:
    NapiWebDevicePermissionDelegate() = default;
    ~NapiWebDevicePermissionDelegate() = default;

    static napi_value JsConstructor(napi_env env, napi_callback_info info);
    static napi_value OnQueryDevicePermission(napi_env env, napi_callback_info info);
    static napi_value OnPermissionRevoked(napi_env env, napi_callback_info info);
    static napi_value OnDevicePicker(napi_env env, napi_callback_info info);
    static napi_value OnDeviceListUpdated(napi_env env, napi_callback_info info);

    static napi_value Init(napi_env env, napi_value exports);
};
} // namespace NWeb
} // namespace OHOS

#endif // NWEB_WEB_DEVICE_PERMISSION_DELEGATE_H
