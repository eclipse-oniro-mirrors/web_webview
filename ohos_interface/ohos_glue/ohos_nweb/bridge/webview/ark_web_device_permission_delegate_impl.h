/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#ifndef ARK_WEB_DEVICE_PERMISSION_DELEGATE_IMPL_H
#define ARK_WEB_DEVICE_PERMISSION_DELEGATE_IMPL_H
#include "ohos_nweb/include/ark_web_device_permission_delegate.h"
#include "include/nweb_device_permission_delegate.h"
#include "base/include/ark_web_base_ref_counted.h"

namespace OHOS::ArkWeb {

class ArkWebDevicePermissionDelegateImpl : public ArkWebDevicePermissionDelegate {
public:
    explicit ArkWebDevicePermissionDelegateImpl(std::shared_ptr<OHOS::NWeb::NWebDevicePermissionDelegate> ref);
    ~ArkWebDevicePermissionDelegateImpl() = default;

    void OnDevicePicker(int32_t nweb_id,
                        const ArkWebString& request_id,
                        const ArkWebDevicePermissionRequestBase& request_info,
                        const ArkWebDevicePermissionDeviceIdentifierVector& devices,
                        ArkWebRefPtr<ArkWebDevicePermissionResultCallback> callback) override;
    void OnQueryDevicePermission(
        int32_t nweb_id, ArkWebRefPtr<ArkWebPermissionOriginsResultCallback> callback) override;
    void OnPermissionRevoked(
        int32_t nweb_id, const ArkWebDevicePermissionRevokedEvent& event) override;
    void OnDeviceListUpdated(int32_t nweb_id, const ArkWebDeviceListUpdateEvent& event) override;

private:
    std::shared_ptr<OHOS::NWeb::NWebDevicePermissionDelegate> real_;
    IMPLEMENT_REFCOUNTING(ArkWebDevicePermissionDelegateImpl);
};
} // namespace OHOS::ArkWeb
#endif // ARK_WEB_DEVICE_PERMISSION_DELEGATE_IMPL_H
