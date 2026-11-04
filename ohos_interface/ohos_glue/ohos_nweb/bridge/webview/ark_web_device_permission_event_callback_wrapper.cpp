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

#include "ohos_nweb/bridge/ark_web_device_permission_event_callback_wrapper.h"

#include "base/bridge/ark_web_bridge_macros.h"
#include "base/include/ark_web_types.h"

namespace OHOS::ArkWeb {

ArkWebDevicePermissionEventCallbackWrapper::ArkWebDevicePermissionEventCallbackWrapper(
    ArkWebRefPtr<ArkWebDevicePermissionEventCallback> ark_web_device_permission_event_callback)
    : ark_web_device_permission_event_callback_(ark_web_device_permission_event_callback)
{}

void ArkWebDevicePermissionEventCallbackWrapper::Reply(const std::string& config)
{
    if (CHECK_REF_PTR_IS_NULL(ark_web_device_permission_event_callback_)) {
        return;
    }

    ArkWebString struct_value = ArkWebStringClassToStruct(config);
    ark_web_device_permission_event_callback_->Reply(struct_value);
    ArkWebStringStructRelease(struct_value);
}

} // namespace OHOS::ArkWeb
