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
#include "ohos_nweb/bridge/ark_web_device_permission_result_callback_wrapper.h"
#include "base/bridge/ark_web_bridge_macros.h"
#include "ohos_nweb/bridge/ark_web_view_struct_utils.h"

namespace OHOS::ArkWeb {

ArkWebDevicePermissionResultCallbackWrapper::ArkWebDevicePermissionResultCallbackWrapper(
    ArkWebRefPtr<ArkWebDevicePermissionResultCallback> ref) : ctocpp_(ref) {}

void ArkWebDevicePermissionResultCallbackWrapper::OnSelect(
    const OHOS::NWeb::NWebDevicePermissionDeviceIdentifier& device)
{
    ArkWebDevicePermissionDeviceIdentifier ark_device =
        ArkWebDevicePermissionDeviceIdentifierClassToStruct(device);
    ctocpp_->OnSelect(ark_device);
    ArkWebStringStructRelease(ark_device.device_key);
    ArkWebStringStructRelease(ark_device.device_name);
}

void ArkWebDevicePermissionResultCallbackWrapper::OnCancel()
{
    ctocpp_->OnCancel();
}

} // namespace OHOS::ArkWeb
