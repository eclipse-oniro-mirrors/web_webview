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

#ifndef ARK_WEB_DEVICE_PERMISSION_DELEGATE_IMPL_H_
#define ARK_WEB_DEVICE_PERMISSION_DELEGATE_IMPL_H_
#pragma once

#include "include/nweb_device_permission_delegate.h"
#include "ohos_nweb/include/ark_web_device_permission_delegate.h"

namespace OHOS::ArkWeb {

class ArkWebDevicePermissionDelegateImpl : public ArkWebDevicePermissionDelegate {
    IMPLEMENT_REFCOUNTING(ArkWebDevicePermissionDelegateImpl);

public:
    explicit ArkWebDevicePermissionDelegateImpl(
        std::shared_ptr<OHOS::NWeb::NWebDevicePermissionDelegate> nweb_device_permission_delegate);
    ~ArkWebDevicePermissionDelegateImpl() = default;

    void OnQueryDevicePermissionOrigins(
        int32_t nweb_id, ArkWebRefPtr<ArkWebPermissionOriginsResultCallback> callback) override;

    void OnPermissionRevoked(
        int32_t nweb_id, const ArkWebDevicePermissionRevokedEvent& event) override;

    void OnDevicePicker(int32_t nweb_id, const ArkWebString& request_id,
        const ArkWebDevicePermissionRequestBase& request_info,
        const ArkWebDevicePermissionDeviceIdentifierVector& devices,
        ArkWebRefPtr<ArkWebDevicePermissionResultCallback> callback) override;

    void OnDeviceListUpdated(
        int32_t nweb_id, const ArkWebDeviceListUpdateEvent& event) override;

private:
    std::shared_ptr<OHOS::NWeb::NWebDevicePermissionDelegate> nweb_device_permission_delegate_;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_DEVICE_PERMISSION_DELEGATE_IMPL_H_
