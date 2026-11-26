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
#include "ohos_nweb/bridge/ark_web_device_permission_delegate_wrapper.h"
#include "base/bridge/ark_web_bridge_macros.h"
#include "ohos_nweb/bridge/ark_web_device_permission_result_callback_impl.h"
#include "ohos_nweb/bridge/ark_web_permission_origins_result_callback_impl.h"

#include "ohos_nweb/bridge/ark_web_core_struct_utils.h"

namespace OHOS::ArkWeb {

ArkWebDevicePermissionDelegateWrapper::ArkWebDevicePermissionDelegateWrapper(
    ArkWebRefPtr<ArkWebDevicePermissionDelegate> ref) : ctocpp_(ref) {}

void ArkWebDevicePermissionDelegateWrapper::OnDevicePicker(
    int32_t nweb_id, const std::string& request_id,
    const OHOS::NWeb::NWebDevicePermissionRequestBase& request_info,
    const std::vector<OHOS::NWeb::NWebDevicePermissionDeviceIdentifier>& devices,
    std::shared_ptr<OHOS::NWeb::NWebDevicePermissionResultCallback> callback)
{
    ArkWebString ark_request_id = ArkWebStringClassToStruct(request_id);
    ArkWebDevicePermissionRequestBase ark_request_info =
        ArkWebDevicePermissionRequestBaseClassToStruct(request_info);
    ArkWebDevicePermissionDeviceIdentifierVector ark_devices =
        ArkWebDevicePermissionDeviceIdentifierVectorClassToStruct(devices);

    if (CHECK_SHARED_PTR_IS_NULL(callback)) {
        ctocpp_->OnDevicePicker(nweb_id, ark_request_id, ark_request_info, ark_devices, nullptr);
    } else {
        ctocpp_->OnDevicePicker(nweb_id, ark_request_id, ark_request_info, ark_devices,
                                new ArkWebDevicePermissionResultCallbackImpl(callback));
    }

    ArkWebStringStructRelease(ark_request_id);
    ArkWebStringStructRelease(ark_request_info.origin);
    ArkWebDevicePermissionDeviceIdentifierVectorStructRelease(ark_devices);
}

void ArkWebDevicePermissionDelegateWrapper::OnQueryDevicePermission(
    int32_t nweb_id, std::shared_ptr<OHOS::NWeb::NWebPermissionOriginsResultCallback> callback)
{
    if (CHECK_SHARED_PTR_IS_NULL(callback)) {
        ctocpp_->OnQueryDevicePermission(nweb_id, nullptr);
    } else {
        ctocpp_->OnQueryDevicePermission(nweb_id, new ArkWebPermissionOriginsResultCallbackImpl(callback));
    }
}

void ArkWebDevicePermissionDelegateWrapper::OnPermissionRevoked(
    int32_t nweb_id, const OHOS::NWeb::NWebDevicePermissionRevokedEvent& event)
{
    ArkWebDevicePermissionRevokedEvent ark_event = ArkWebDevicePermissionRevokedEventClassToStruct(event);

    ctocpp_->OnPermissionRevoked(nweb_id, ark_event);

    ArkWebDevicePermissionRevokedEventStructRelease(ark_event);
}

void ArkWebDevicePermissionDelegateWrapper::OnDeviceListUpdated(
    int32_t nweb_id, const OHOS::NWeb::NWebDeviceListUpdateEvent& event)
{
    ArkWebDeviceListUpdateEvent ark_event = ArkWebDeviceListUpdateEventClassToStruct(event);

    ctocpp_->OnDeviceListUpdated(nweb_id, ark_event);

    ArkWebDeviceListUpdateEventStructRelease(ark_event);
}

} // namespace OHOS::ArkWeb
