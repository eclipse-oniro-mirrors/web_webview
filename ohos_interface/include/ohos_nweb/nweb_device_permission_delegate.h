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

#ifndef NWEB_DEVICE_PERMISSION_DELEGATE_H
#define NWEB_DEVICE_PERMISSION_DELEGATE_H

#include <memory>
#include <string>
#include <vector>

#include "nweb_export.h"

namespace OHOS::NWeb {

enum class NWebDevicePermissionHardwareType : int32_t {
    USB = 0,
    SERIAL = 1,
    HID = 2,
    BLUETOOTH = 3,
};

enum class NWebDeviceListUpdateAction : int32_t {
    ADD = 0,
    REMOVE = 1,
};

enum class NWebDeviceGuardPolicy : int32_t {
    ASK = 0,
    BLOCK = 1,
    DEFAULT = 2,
};

struct NWebDevicePermissionDeviceIdentifier {
    int32_t vendor_id = 0;
    int32_t product_id = 0;
    std::string device_key;
    std::string device_name;
};

struct NWebDevicePermissionRequestBase {
    NWebDevicePermissionHardwareType hardware_type = NWebDevicePermissionHardwareType::USB;
    std::string origin;
    bool is_incognito = false;
};

struct NWebDevicePermissionRevokedEvent {
    NWebDevicePermissionHardwareType hardware_type = NWebDevicePermissionHardwareType::USB;
    std::string origin;
    bool is_incognito = false;
    NWebDevicePermissionDeviceIdentifier device;
};

struct NWebDeviceListUpdateEvent {
    std::string request_id;
    NWebDeviceListUpdateAction action = NWebDeviceListUpdateAction::ADD;
    std::vector<NWebDevicePermissionDeviceIdentifier> devices;
};

/**
 * @brief Result callback for querying the complete device permission
 *        configuration. The delegate implementation should call OnReply
 *        synchronously with the serialized json configuration.
 */
class NWebPermissionOriginsResultCallback {
public:
    virtual ~NWebPermissionOriginsResultCallback() = default;

    /**
     * @brief Reply the complete device permission configuration in json format.
     *
     * @param config the serialized json configuration string.
     */
    virtual void OnReply(const std::string& config) = 0;
};

/**
 * @brief Result callback for a device permission select request. The delegate
 *        implementation should call OnSelect when the user selects a device, or
 *        call OnCancel when the user cancels the request.
 */
class NWebDevicePermissionResultCallback {
public:
    virtual ~NWebDevicePermissionResultCallback() = default;

    /**
     * @brief Grant permission to the selected device.
     *
     * @param device the device selected by the user.
     */
    virtual void OnSelect(const NWebDevicePermissionDeviceIdentifier& device) = 0;

    /**
     * @brief Cancel the permission request.
     */
    virtual void OnCancel() = 0;
};

/**
 * @brief Delegate for web device permission events. The host application
 *        implements this interface to receive device permission requests
 *        and events.
 */
class NWebDevicePermissionDelegate {
public:
    virtual ~NWebDevicePermissionDelegate() = default;

    /**
     * @brief Called to query the complete device permission configuration.
     *        Triggered immediately after the delegate is set.
     *
     * @param nweb_id the id of the nweb instance.
     * @param callback the result callback to reply the configuration.
     */
    virtual void OnQueryDevicePermissionOrigins(int32_t nweb_id,
        std::shared_ptr<NWebPermissionOriginsResultCallback> callback) = 0;

    /**
     * @brief Called when the web page requests to revoke a device permission.
     *
     * @param nweb_id the id of the nweb instance.
     * @param event the revocation event data.
     */
    virtual void OnPermissionRevoked(int32_t nweb_id,
        const NWebDevicePermissionRevokedEvent& event) = 0;

    /**
     * @brief Called when the web page requests to select a device.
     *
     * @param nweb_id the id of the nweb instance.
     * @param request_id the unique request identifier.
     * @param request_info the base information of the request.
     * @param devices the list of devices available for selection.
     * @param callback the result callback to return the selection result.
     */
    virtual void OnDevicePicker(int32_t nweb_id, const std::string& request_id,
        const NWebDevicePermissionRequestBase& request_info,
        const std::vector<NWebDevicePermissionDeviceIdentifier>& devices,
        std::shared_ptr<NWebDevicePermissionResultCallback> callback) = 0;

    /**
     * @brief Called when the device list is updated while the picker is shown.
     *
     * @param nweb_id the id of the nweb instance.
     * @param event the device list update event data.
     */
    virtual void OnDeviceListUpdated(int32_t nweb_id,
        const NWebDeviceListUpdateEvent& event) = 0;
};

} // namespace OHOS::NWeb

#endif // NWEB_DEVICE_PERMISSION_DELEGATE_H
