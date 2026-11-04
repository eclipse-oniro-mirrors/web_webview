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

#ifndef ARK_WEB_DEVICE_PERMISSION_DELEGATE_H_
#define ARK_WEB_DEVICE_PERMISSION_DELEGATE_H_
#pragma once

#include "ohos_nweb/include/ark_web_device_permission_event_callback.h"
#include "ohos_nweb/include/ark_web_device_permission_result_callback.h"
#include "ohos_nweb/include/ark_web_nweb_structs.h"

#include "base/include/ark_web_base_ref_counted.h"

namespace OHOS::ArkWeb {

/*--ark web(source=webview)--*/
class ArkWebDevicePermissionDelegate : public virtual ArkWebBaseRefCounted {
public:
    /*--ark web()--*/
    virtual void OnQueryDevicePermission(ArkWebRefPtr<ArkWebDevicePermissionEventCallback> callback) = 0;

    /*--ark web()--*/
    virtual void OnPermissionRevoked(const ArkWebDevicePermissionRevokedEvent& event) = 0;

    /*--ark web()--*/
    virtual void OnDevicePicker(const ArkWebDevicePermissionRequest& request,
        ArkWebRefPtr<ArkWebDevicePermissionResultCallback> callback) = 0;

    /*--ark web()--*/
    virtual void OnDeviceListUpdated(const ArkWebDevicePermissionListUpdateEvent& event) = 0;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_DEVICE_PERMISSION_DELEGATE_H_
