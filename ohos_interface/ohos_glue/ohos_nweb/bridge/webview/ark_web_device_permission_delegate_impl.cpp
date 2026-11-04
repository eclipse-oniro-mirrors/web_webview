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

#include "ohos_nweb/bridge/ark_web_device_permission_delegate_impl.h"

#include "base/bridge/ark_web_bridge_macros.h"
#include "ohos_nweb/bridge/ark_web_device_permission_event_callback_wrapper.h"
#include "ohos_nweb/bridge/ark_web_device_permission_result_callback_wrapper.h"
#include "ohos_nweb/bridge/ark_web_device_permission_struct_utils.h"

namespace OHOS::ArkWeb {

ArkWebDevicePermissionDelegateImpl::ArkWebDevicePermissionDelegateImpl(
    std::shared_ptr<OHOS::NWeb::NWebDevicePermissionDelegate> nweb_device_permission_delegate)
    : nweb_device_permission_delegate_(nweb_device_permission_delegate)
{}

void ArkWebDevicePermissionDelegateImpl::OnQueryDevicePermission(
    ArkWebRefPtr<ArkWebDevicePermissionEventCallback> callback)
{
    if (CHECK_SHARED_PTR_IS_NULL(nweb_device_permission_delegate_)) {
        return;
    }

    std::shared_ptr<OHOS::NWeb::NWebDevicePermissionEventCallback> nweb_callback = nullptr;
    if (!CHECK_REF_PTR_IS_NULL(callback)) {
        nweb_callback = std::make_shared<ArkWebDevicePermissionEventCallbackWrapper>(callback);
    }

    nweb_device_permission_delegate_->OnQueryDevicePermission(nweb_callback);
}

void ArkWebDevicePermissionDelegateImpl::OnPermissionRevoked(
    const ArkWebDevicePermissionRevokedEvent& event)
{
    if (CHECK_SHARED_PTR_IS_NULL(nweb_device_permission_delegate_)) {
        return;
    }

    OHOS::NWeb::NWebDevicePermissionRevokedEvent nweb_event =
        ArkWebDevicePermissionRevokedEventStructToClass(event);
    nweb_device_permission_delegate_->OnPermissionRevoked(nweb_event);
}

void ArkWebDevicePermissionDelegateImpl::OnDevicePicker(const ArkWebDevicePermissionRequest& request,
    ArkWebRefPtr<ArkWebDevicePermissionResultCallback> callback)
{
    if (CHECK_SHARED_PTR_IS_NULL(nweb_device_permission_delegate_)) {
        return;
    }

    OHOS::NWeb::NWebDevicePermissionRequest nweb_request = ArkWebDevicePermissionRequestStructToClass(request);
    std::shared_ptr<OHOS::NWeb::NWebDevicePermissionResultCallback> nweb_callback = nullptr;
    if (!CHECK_REF_PTR_IS_NULL(callback)) {
        nweb_callback = std::make_shared<ArkWebDevicePermissionResultCallbackWrapper>(callback);
    }

    nweb_device_permission_delegate_->OnDevicePicker(nweb_request, nweb_callback);
}

void ArkWebDevicePermissionDelegateImpl::OnDeviceListUpdated(
    const ArkWebDevicePermissionListUpdateEvent& event)
{
    if (CHECK_SHARED_PTR_IS_NULL(nweb_device_permission_delegate_)) {
        return;
    }

    OHOS::NWeb::NWebDevicePermissionListUpdateEvent nweb_event =
        ArkWebDevicePermissionListUpdateEventStructToClass(event);
    nweb_device_permission_delegate_->OnDeviceListUpdated(nweb_event);
}

} // namespace OHOS::ArkWeb
