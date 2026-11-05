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

#include "ohos_nweb/bridge/ark_web_device_permission_delegate_wrapper.h"

#include "base/bridge/ark_web_bridge_macros.h"
#include "base/include/ark_web_types.h"
#include "ohos_nweb/bridge/ark_web_core_struct_utils.h"
#include "ohos_nweb/bridge/ark_web_device_permission_result_callback_impl.h"
#include "ohos_nweb/bridge/ark_web_permission_origins_result_callback_impl.h"

namespace OHOS::ArkWeb {

ArkWebDevicePermissionDelegateWrapper::ArkWebDevicePermissionDelegateWrapper(
    ArkWebRefPtr<ArkWebDevicePermissionDelegate> ark_web_device_permission_delegate)
    : ark_web_device_permission_delegate_(ark_web_device_permission_delegate)
{}

void ArkWebDevicePermissionDelegateWrapper::OnQueryDevicePermissionOrigins(int32_t nweb_id,
    std::shared_ptr<OHOS::NWeb::NWebPermissionOriginsResultCallback> callback)
{
    if (CHECK_REF_PTR_IS_NULL(ark_web_device_permission_delegate_)) {
        return;
    }

    ArkWebRefPtr<ArkWebPermissionOriginsResultCallback> ark_web_callback = nullptr;
    if (!CHECK_SHARED_PTR_IS_NULL(callback)) {
        ark_web_callback = new ArkWebPermissionOriginsResultCallbackImpl(callback);
    }

    ark_web_device_permission_delegate_->OnQueryDevicePermissionOrigins(nweb_id, ark_web_callback);
}

void ArkWebDevicePermissionDelegateWrapper::OnPermissionRevoked(int32_t nweb_id,
    const OHOS::NWeb::NWebDevicePermissionRevokedEvent& event)
{
    if (CHECK_REF_PTR_IS_NULL(ark_web_device_permission_delegate_)) {
        return;
    }

    ArkWebDevicePermissionRevokedEvent struct_event = ArkWebDevicePermissionRevokedEventClassToStruct(event);
    ark_web_device_permission_delegate_->OnPermissionRevoked(nweb_id, struct_event);
    ArkWebDevicePermissionRevokedEventStructRelease(struct_event);
}

void ArkWebDevicePermissionDelegateWrapper::OnDevicePicker(int32_t nweb_id, const std::string& request_id,
    const OHOS::NWeb::NWebDevicePermissionRequestBase& request_info,
    const std::vector<OHOS::NWeb::NWebDevicePermissionDeviceIdentifier>& devices,
    std::shared_ptr<OHOS::NWeb::NWebDevicePermissionResultCallback> callback)
{
    if (CHECK_REF_PTR_IS_NULL(ark_web_device_permission_delegate_)) {
        return;
    }

    ArkWebString struct_request_id = ArkWebStringClassToStruct(request_id);
    ArkWebDevicePermissionRequestBase struct_request_info =
        ArkWebDevicePermissionRequestBaseClassToStruct(request_info);
    ArkWebDevicePermissionDeviceIdentifierVector struct_devices =
        ArkWebDevicePermissionDeviceIdentifierVectorClassToStruct(devices);
    ArkWebRefPtr<ArkWebDevicePermissionResultCallback> ark_web_callback = nullptr;
    if (!CHECK_SHARED_PTR_IS_NULL(callback)) {
        ark_web_callback = new ArkWebDevicePermissionResultCallbackImpl(callback);
    }

    ark_web_device_permission_delegate_->OnDevicePicker(
        nweb_id, struct_request_id, struct_request_info, struct_devices, ark_web_callback);

    ArkWebStringStructRelease(struct_request_id);
    ArkWebDevicePermissionRequestBaseStructRelease(struct_request_info);
    ArkWebDevicePermissionDeviceIdentifierVectorStructRelease(struct_devices);
}

void ArkWebDevicePermissionDelegateWrapper::OnDeviceListUpdated(int32_t nweb_id,
    const OHOS::NWeb::NWebDeviceListUpdateEvent& event)
{
    if (CHECK_REF_PTR_IS_NULL(ark_web_device_permission_delegate_)) {
        return;
    }

    ArkWebDeviceListUpdateEvent struct_event = ArkWebDeviceListUpdateEventClassToStruct(event);
    ark_web_device_permission_delegate_->OnDeviceListUpdated(nweb_id, struct_event);
    ArkWebDeviceListUpdateEventStructRelease(struct_event);
}

} // namespace OHOS::ArkWeb
