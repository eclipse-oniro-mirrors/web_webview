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

#ifndef NWEB_DEVICE_PERMISSION_H
#define NWEB_DEVICE_PERMISSION_H

#include <memory>
#include <string>
#include <vector>

#include "nweb_export.h"

namespace OHOS::NWeb {

enum class NWebHardwareType : int32_t {
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

class NWebDeviceIdentifier {
public:
    virtual ~NWebDeviceIdentifier() = default;

    virtual int32_t GetVendorId() = 0;

    virtual int32_t GetProductId() = 0;

    virtual std::string GetDeviceKey() = 0;

    virtual std::string GetDeviceName() = 0;
};

class NWebPermissionRequestBase {
public:
    virtual ~NWebPermissionRequestBase() = default;

    virtual NWebHardwareType GetHardwareType() = 0;

    virtual std::string GetOrigin() = 0;

    virtual bool GetIsIncognito() = 0;
};

class NWebDevicePermissionRevokedEvent {
public:
    virtual ~NWebDevicePermissionRevokedEvent() = default;

    virtual NWebHardwareType GetHardwareType() = 0;

    virtual std::string GetOrigin() = 0;

    virtual bool GetIsIncognito() = 0;

    virtual std::shared_ptr<NWebDeviceIdentifier> GetDevice() = 0;
};

class NWebDeviceListUpdateEvent {
public:
    virtual ~NWebDeviceListUpdateEvent() = default;

    virtual std::string GetRequestId() = 0;

    virtual NWebDeviceListUpdateAction GetAction() = 0;

    virtual std::vector<std::shared_ptr<NWebDeviceIdentifier>> GetDevices() = 0;
};

class NWebDevicePermissionOriginsEvent {
public:
    virtual ~NWebDevicePermissionOriginsEvent() = default;

    virtual void Reply(const std::string& config) = 0;
};

class NWebDevicePermissionRequest {
public:
    virtual ~NWebDevicePermissionRequest() = default;

    virtual std::shared_ptr<NWebPermissionRequestBase> GetRequestInfo() = 0;

    virtual std::string GetRequestId() = 0;

    virtual std::vector<std::shared_ptr<NWebDeviceIdentifier>> GetDeviceList() = 0;

    virtual void Select(std::shared_ptr<NWebDeviceIdentifier> device) = 0;

    virtual void Cancel() = 0;
};

class NWebDevicePermissionDelegate {
public:
    virtual ~NWebDevicePermissionDelegate() = default;

    virtual void OnQueryDevicePermissionOrigins(
        std::shared_ptr<NWebDevicePermissionOriginsEvent> event) = 0;

    virtual void OnPermissionRevoked(
        std::shared_ptr<NWebDevicePermissionRevokedEvent> event) = 0;

    virtual void OnDevicePicker(std::shared_ptr<NWebDevicePermissionRequest> request) = 0;

    virtual void OnDeviceListUpdated(std::shared_ptr<NWebDeviceListUpdateEvent> event) = 0;
};

} // namespace OHOS::NWeb

#endif // NWEB_DEVICE_PERMISSION_H
