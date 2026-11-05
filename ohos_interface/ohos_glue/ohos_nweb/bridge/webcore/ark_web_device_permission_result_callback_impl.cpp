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

#include "ohos_nweb/bridge/ark_web_device_permission_result_callback_impl.h"

#include "base/bridge/ark_web_bridge_macros.h"
#include "ohos_nweb/bridge/ark_web_core_struct_utils.h"

namespace OHOS::ArkWeb {

ArkWebDevicePermissionResultCallbackImpl::ArkWebDevicePermissionResultCallbackImpl(
    std::shared_ptr<OHOS::NWeb::NWebDevicePermissionResultCallback> nweb_device_permission_result_callback)
    : nweb_device_permission_result_callback_(nweb_device_permission_result_callback)
{}

void ArkWebDevicePermissionResultCallbackImpl::OnSelect(
    const ArkWebDevicePermissionDeviceIdentifier& device)
{
    if (CHECK_SHARED_PTR_IS_NULL(nweb_device_permission_result_callback_)) {
        return;
    }

    OHOS::NWeb::NWebDevicePermissionDeviceIdentifier class_value =
        ArkWebDevicePermissionDeviceIdentifierStructToClass(device);
    nweb_device_permission_result_callback_->OnSelect(class_value);
}

void ArkWebDevicePermissionResultCallbackImpl::OnCancel()
{
    if (CHECK_SHARED_PTR_IS_NULL(nweb_device_permission_result_callback_)) {
        return;
    }

    nweb_device_permission_result_callback_->OnCancel();
}

} // namespace OHOS::ArkWeb
