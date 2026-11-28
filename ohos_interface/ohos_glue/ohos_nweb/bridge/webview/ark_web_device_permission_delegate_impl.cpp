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
#include "ohos_nweb/bridge/ark_web_device_permission_delegate_impl.h"
#include "base/include/ark_web_types.h"
#include "base/bridge/ark_web_bridge_macros.h"
#include "ohos_nweb/bridge/ark_web_device_permission_result_callback_wrapper.h"
#include "ohos_nweb/bridge/ark_web_permission_origins_result_callback_wrapper.h"
#include "ohos_nweb/bridge/ark_web_view_struct_utils.h"

namespace OHOS::ArkWeb {

ArkWebDevicePermissionDelegateImpl::ArkWebDevicePermissionDelegateImpl(
    std::shared_ptr<OHOS::NWeb::NWebDevicePermissionDelegate> ref) : real_(ref) {}

void ArkWebDevicePermissionDelegateImpl::OnDevicePicker(
    int32_t nweb_id,
    const ArkWebString& request_id,
    const ArkWebDevicePermissionRequestBase& request_info,
    const ArkWebDevicePermissionDeviceIdentifierVector& devices,
    ArkWebRefPtr<ArkWebDevicePermissionResultCallback> callback)
{
    ARK_WEB_BRIDGE_INFO_LOG("[DEVICE_PERM_DBG] Impl::OnDevicePicker entry, nweb_id=%{public}d", nweb_id);
    std::shared_ptr<OHOS::NWeb::NWebDevicePermissionResultCallback> result_callback;
    if (!CHECK_REF_PTR_IS_NULL(callback)) {
        result_callback = std::make_shared<ArkWebDevicePermissionResultCallbackWrapper>(callback);
    }
    real_->OnDevicePicker(nweb_id, ArkWebStringStructToClass(request_id),
                          ArkWebDevicePermissionRequestBaseStructToClass(request_info),
                          ArkWebDevicePermissionDeviceIdentifierVectorStructToClass(devices),
                          result_callback);
}

void ArkWebDevicePermissionDelegateImpl::OnQueryDevicePermission(
    int32_t nweb_id,
    ArkWebRefPtr<ArkWebPermissionOriginsResultCallback> callback)
{
    ARK_WEB_BRIDGE_INFO_LOG(
        "[DEVICE_PERM_DBG] Impl::OnQueryDevicePermission entry, nweb_id=%{public}d", nweb_id);
    if (CHECK_REF_PTR_IS_NULL(callback)) {
        real_->OnQueryDevicePermission(nweb_id, nullptr);
        return;
    }

    real_->OnQueryDevicePermission(
        nweb_id, std::make_shared<ArkWebPermissionOriginsResultCallbackWrapper>(callback));
}

void ArkWebDevicePermissionDelegateImpl::OnPermissionRevoked(
    int32_t nweb_id, const ArkWebDevicePermissionRevokedEvent& event)
{
    real_->OnPermissionRevoked(nweb_id, ArkWebDevicePermissionRevokedEventStructToClass(event));
}

void ArkWebDevicePermissionDelegateImpl::OnDeviceListUpdated(
    int32_t nweb_id, const ArkWebDeviceListUpdateEvent& event)
{
    ARK_WEB_BRIDGE_INFO_LOG("[DEVICE_PERM_DBG] Impl::OnDeviceListUpdated entry, nweb_id=%{public}d", nweb_id);
    real_->OnDeviceListUpdated(nweb_id, ArkWebDeviceListUpdateEventStructToClass(event));
}

} // namespace OHOS::ArkWeb
