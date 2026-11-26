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

#ifndef NWEB_DEVICE_PERMISSION_DELEGATE_H
#define NWEB_DEVICE_PERMISSION_DELEGATE_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "nweb_export.h"

namespace OHOS::NWeb {

// Hardware type for device permission requests. Mirrors the kernel-side
// NWebHardwareType enum.
enum class NWebDevicePermissionHardwareType : int32_t {
    USB = 0,
    SERIAL = 1,
    HID = 2,
    BLUETOOTH = 3,
};

// Device list update action for the permission picker.
enum class NWebDeviceListUpdateAction : int32_t {
    ADD = 0,
    REMOVE = 1,
};

// Guard policy for device permission requests.
enum class NWebDeviceGuardPolicy : int32_t {
    ASK = 0,
    BLOCK = 1,
    DEFAULT = 2,
};

// Device identifier for a USB/HID/Serial/Bluetooth device.
struct NWebDevicePermissionDeviceIdentifier {
    int32_t vendor_id = 0;
    int32_t product_id = 0;
    std::string device_key;
    std::string device_name;
};

// Base metadata for a device permission request.
struct NWebDevicePermissionRequestBase {
    NWebDevicePermissionHardwareType hardware_type =
        NWebDevicePermissionHardwareType::USB;
    std::string origin;
    bool is_incognito = false;
};

// Event data for permission revocation notification.
struct NWebDevicePermissionRevokedEvent {
    NWebDevicePermissionHardwareType hardware_type =
        NWebDevicePermissionHardwareType::USB;
    std::string origin;
    bool is_incognito = false;
    NWebDevicePermissionDeviceIdentifier device;
};

// Event data for device list updates during picker display.
struct NWebDeviceListUpdateEvent {
    std::string request_id;
    NWebDeviceListUpdateAction action = NWebDeviceListUpdateAction::ADD;
    std::vector<NWebDevicePermissionDeviceIdentifier> devices;
};

// Result callback invoked by the application to deliver the user's device
// selection back to the kernel. The kernel creates this object and passes it
// to NWebDevicePermissionDelegate::OnDevicePicker; the application calls
// OnSelect() or OnCancel() exactly once to resolve the request.
class OHOS_NWEB_EXPORT NWebDevicePermissionResultCallback {
public:
    NWebDevicePermissionResultCallback() = default;
    virtual ~NWebDevicePermissionResultCallback() = default;

    // Called when the user selects a device. |device| carries the selected
    // device identifier; its device_key is used to look up the device in the
    // kernel's device map.
    virtual void OnSelect(const NWebDevicePermissionDeviceIdentifier& device) = 0;

    // Called when the user dismisses the picker without selecting a device.
    virtual void OnCancel() = 0;
};

// Result callback for OnQueryDevicePermission. The application calls
// OnReply() to return the full device permission and guard configuration as
// a JSON string.
class OHOS_NWEB_EXPORT NWebPermissionOriginsResultCallback {
public:
    NWebPermissionOriginsResultCallback() = default;
    virtual ~NWebPermissionOriginsResultCallback() = default;

    virtual void OnReply(const std::string& config) = 0;
};

// Delegate registered by the webview layer. The kernel invokes these methods
// to notify the application of device permission events or query permission
// status.
class OHOS_NWEB_EXPORT NWebDevicePermissionDelegate {
public:
    NWebDevicePermissionDelegate() = default;

    virtual ~NWebDevicePermissionDelegate() = default;

    // Called by the kernel when a webpage invokes requestDevice().
    virtual void OnDevicePicker(int32_t nweb_id, const std::string& request_id,
                                const NWebDevicePermissionRequestBase& request_info,
                                const std::vector<NWebDevicePermissionDeviceIdentifier>& devices,
                                std::shared_ptr<NWebDevicePermissionResultCallback> callback) = 0;

    // Called by the kernel immediately after SetDevicePermissionDelegate
    // completes. The application should call callback->OnReply() to return the
    // full device permission and guard configuration as a JSON string.
    virtual void OnQueryDevicePermission(
        int32_t nweb_id, std::shared_ptr<NWebPermissionOriginsResultCallback> callback) = 0;

    // Called by the kernel when a webpage invokes forget() to revoke permission.
    // Notification-only: no reply needed. The application should remove the
    // corresponding permission record.
    virtual void OnPermissionRevoked(int32_t nweb_id, const NWebDevicePermissionRevokedEvent& event) = 0;

    // Called by the kernel when the device list changes while the picker UI is
    // displayed. Notification-only: no reply needed. The application should
    // update the picker list according to the action type.
    virtual void OnDeviceListUpdated(int32_t nweb_id, const NWebDeviceListUpdateEvent& event) = 0;
};

} // namespace OHOS::NWeb

#endif // NWEB_DEVICE_PERMISSION_DELEGATE_H
