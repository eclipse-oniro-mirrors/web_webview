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

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "nweb_device_permission.h"
#include "auto_napi_ref.h"

namespace OHOS {
namespace NWeb {

class NWebDeviceIdentifierImpl : public NWebDeviceIdentifier {
public:
    NWebDeviceIdentifierImpl() = default;
    ~NWebDeviceIdentifierImpl() override = default;

    int32_t GetVendorId() override
    {
        return vendorId_;
    }

    int32_t GetProductId() override
    {
        return productId_;
    }

    std::string GetDeviceKey() override
    {
        return deviceKey_;
    }

    std::string GetDeviceName() override
    {
        return deviceName_;
    }

    void SetVendorId(int32_t vendorId)
    {
        vendorId_ = vendorId;
    }

    void SetProductId(int32_t productId)
    {
        productId_ = productId;
    }

    void SetDeviceKey(const std::string& deviceKey)
    {
        deviceKey_ = deviceKey;
    }

    void SetDeviceName(const std::string& deviceName)
    {
        deviceName_ = deviceName;
    }

private:
    int32_t vendorId_ = 0;
    int32_t productId_ = 0;
    std::string deviceKey_;
    std::string deviceName_;
};

class WebDevicePermissionDelegate : public NWebDevicePermissionDelegate {
public:
    explicit WebDevicePermissionDelegate(napi_env env);
    ~WebDevicePermissionDelegate() override;

    void OnQueryDevicePermissionOrigins(
        std::shared_ptr<NWebDevicePermissionOriginsEvent> event) override;

    void OnPermissionRevoked(
        std::shared_ptr<NWebDevicePermissionRevokedEvent> event) override;

    void OnDevicePicker(std::shared_ptr<NWebDevicePermissionRequest> request) override;

    void OnDeviceListUpdated(std::shared_ptr<NWebDeviceListUpdateEvent> event) override;

    void PutOnQueryDevicePermissionOrigins(napi_env env, napi_value callback);
    void PutOnPermissionRevoked(napi_env env, napi_value callback);
    void PutOnDevicePicker(napi_env env, napi_value callback);
    void PutOnDeviceListUpdated(napi_env env, napi_value callback);

    napi_env GetEnv()
    {
        return env_;
    }

    napi_ref delegate_ = nullptr;

private:
    napi_env env_ = nullptr;
    napi_ref on_query_origins_callback_ = nullptr;
    napi_ref on_permission_revoked_callback_ = nullptr;
    napi_ref on_device_picker_callback_ = nullptr;
    napi_ref on_device_list_updated_callback_ = nullptr;
};

class NapiWebDevicePermissionDelegate {
public:
    NapiWebDevicePermissionDelegate() = default;
    ~NapiWebDevicePermissionDelegate() = default;

    static napi_value JsConstructor(napi_env env, napi_callback_info info);
    static napi_value OnQueryDevicePermissionOrigins(napi_env env, napi_callback_info info);
    static napi_value OnPermissionRevoked(napi_env env, napi_callback_info info);
    static napi_value OnDevicePicker(napi_env env, napi_callback_info info);
    static napi_value OnDeviceListUpdated(napi_env env, napi_callback_info info);

    static napi_value Init(napi_env env, napi_value exports);
};
} // namespace NWeb
} // namespace OHOS

#endif // NWEB_WEB_DEVICE_PERMISSION_DELEGATE_H
