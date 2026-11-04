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

#include "ohos_nweb/bridge/ark_web_device_permission_struct_utils.h"

#include "base/include/ark_web_memory.h"
#include "base/include/ark_web_types.h"
namespace OHOS::ArkWeb {

ArkWebDevicePermissionDeviceIdentifier ArkWebDevicePermissionDeviceIdentifierClassToStruct(
    const OHOS::NWeb::NWebDevicePermissionDeviceIdentifier& class_value)
{
    ArkWebDevicePermissionDeviceIdentifier struct_value;
    struct_value.vendor_id = class_value.vendor_id;
    struct_value.product_id = class_value.product_id;
    struct_value.device_key = ArkWebStringClassToStruct(class_value.device_key);
    struct_value.device_name = ArkWebStringClassToStruct(class_value.device_name);
    return struct_value;
}

OHOS::NWeb::NWebDevicePermissionDeviceIdentifier ArkWebDevicePermissionDeviceIdentifierStructToClass(
    const ArkWebDevicePermissionDeviceIdentifier& struct_value)
{
    OHOS::NWeb::NWebDevicePermissionDeviceIdentifier class_value;
    class_value.vendor_id = struct_value.vendor_id;
    class_value.product_id = struct_value.product_id;
    class_value.device_key = ArkWebStringStructToClass(struct_value.device_key);
    class_value.device_name = ArkWebStringStructToClass(struct_value.device_name);
    return class_value;
}

void ArkWebDevicePermissionDeviceIdentifierStructRelease(ArkWebDevicePermissionDeviceIdentifier& struct_value)
{
    ArkWebStringStructRelease(struct_value.device_key);
    ArkWebStringStructRelease(struct_value.device_name);
}

ArkWebDevicePermissionDeviceIdentifierVector ArkWebDevicePermissionDeviceIdentifierVectorClassToStruct(
    const std::vector<OHOS::NWeb::NWebDevicePermissionDeviceIdentifier>& class_value)
{
    ArkWebDevicePermissionDeviceIdentifierVector struct_value = {
        .size = static_cast<int>(class_value.size()), .ark_web_mem_free_func = ArkWebMemFree
    };
    if (struct_value.size > 0) {
        struct_value.value = (ArkWebDevicePermissionDeviceIdentifier*)ArkWebMemMalloc(
            sizeof(ArkWebDevicePermissionDeviceIdentifier) * struct_value.size);
        if (struct_value.value == nullptr) {
            struct_value.size = 0;
            return struct_value;
        }

        int count = 0;
        for (auto it = class_value.begin(); it != class_value.end(); it++) {
            struct_value.value[count] = ArkWebDevicePermissionDeviceIdentifierClassToStruct(*it);
            count++;
        }
    }

    return struct_value;
}

std::vector<OHOS::NWeb::NWebDevicePermissionDeviceIdentifier> ArkWebDevicePermissionDeviceIdentifierVectorStructToClass(
    const ArkWebDevicePermissionDeviceIdentifierVector& struct_value)
{
    std::vector<OHOS::NWeb::NWebDevicePermissionDeviceIdentifier> class_value;
    for (int count = 0; count < struct_value.size; count++) {
        class_value.push_back(ArkWebDevicePermissionDeviceIdentifierStructToClass(struct_value.value[count]));
    }

    return class_value;
}

void ArkWebDevicePermissionDeviceIdentifierVectorStructRelease(
    ArkWebDevicePermissionDeviceIdentifierVector& struct_value)
{
    for (int count = 0; count < struct_value.size; count++) {
        ArkWebDevicePermissionDeviceIdentifierStructRelease(struct_value.value[count]);
    }

    if (struct_value.ark_web_mem_free_func != nullptr && struct_value.value != nullptr) {
        struct_value.ark_web_mem_free_func(struct_value.value);
        struct_value.value = nullptr;
    }
    struct_value.size = 0;
}

ArkWebDevicePermissionRequestBase ArkWebDevicePermissionRequestBaseClassToStruct(
    const OHOS::NWeb::NWebDevicePermissionRequestBase& class_value)
{
    ArkWebDevicePermissionRequestBase struct_value;
    struct_value.hardware_type = static_cast<int32_t>(class_value.hardware_type);
    struct_value.origin = ArkWebStringClassToStruct(class_value.origin);
    struct_value.is_incognito = class_value.is_incognito;
    return struct_value;
}

OHOS::NWeb::NWebDevicePermissionRequestBase ArkWebDevicePermissionRequestBaseStructToClass(
    const ArkWebDevicePermissionRequestBase& struct_value)
{
    OHOS::NWeb::NWebDevicePermissionRequestBase class_value;
    class_value.hardware_type = static_cast<OHOS::NWeb::NWebDevicePermissionHardwareType>(
        struct_value.hardware_type);
    class_value.origin = ArkWebStringStructToClass(struct_value.origin);
    class_value.is_incognito = struct_value.is_incognito;
    return class_value;
}

void ArkWebDevicePermissionRequestBaseStructRelease(ArkWebDevicePermissionRequestBase& struct_value)
{
    ArkWebStringStructRelease(struct_value.origin);
}

ArkWebDevicePermissionRevokedEvent ArkWebDevicePermissionRevokedEventClassToStruct(
    const OHOS::NWeb::NWebDevicePermissionRevokedEvent& class_value)
{
    ArkWebDevicePermissionRevokedEvent struct_value;
    struct_value.hardware_type = static_cast<int32_t>(class_value.hardware_type);
    struct_value.origin = ArkWebStringClassToStruct(class_value.origin);
    struct_value.is_incognito = class_value.is_incognito;
    struct_value.device = ArkWebDevicePermissionDeviceIdentifierClassToStruct(class_value.device);
    return struct_value;
}

OHOS::NWeb::NWebDevicePermissionRevokedEvent ArkWebDevicePermissionRevokedEventStructToClass(
    const ArkWebDevicePermissionRevokedEvent& struct_value)
{
    OHOS::NWeb::NWebDevicePermissionRevokedEvent class_value;
    class_value.hardware_type = static_cast<OHOS::NWeb::NWebDevicePermissionHardwareType>(
        struct_value.hardware_type);
    class_value.origin = ArkWebStringStructToClass(struct_value.origin);
    class_value.is_incognito = struct_value.is_incognito;
    class_value.device = ArkWebDevicePermissionDeviceIdentifierStructToClass(struct_value.device);
    return class_value;
}

void ArkWebDevicePermissionRevokedEventStructRelease(ArkWebDevicePermissionRevokedEvent& struct_value)
{
    ArkWebStringStructRelease(struct_value.origin);
    ArkWebDevicePermissionDeviceIdentifierStructRelease(struct_value.device);
}

ArkWebDevicePermissionListUpdateEvent ArkWebDevicePermissionListUpdateEventClassToStruct(
    const OHOS::NWeb::NWebDevicePermissionListUpdateEvent& class_value)
{
    ArkWebDevicePermissionListUpdateEvent struct_value;
    struct_value.request_id = ArkWebStringClassToStruct(class_value.request_id);
    struct_value.action = static_cast<int32_t>(class_value.action);
    struct_value.devices = ArkWebDevicePermissionDeviceIdentifierVectorClassToStruct(class_value.devices);
    return struct_value;
}

OHOS::NWeb::NWebDevicePermissionListUpdateEvent ArkWebDevicePermissionListUpdateEventStructToClass(
    const ArkWebDevicePermissionListUpdateEvent& struct_value)
{
    OHOS::NWeb::NWebDevicePermissionListUpdateEvent class_value;
    class_value.request_id = ArkWebStringStructToClass(struct_value.request_id);
    class_value.action = static_cast<OHOS::NWeb::NWebDevicePermissionListUpdateAction>(struct_value.action);
    class_value.devices = ArkWebDevicePermissionDeviceIdentifierVectorStructToClass(struct_value.devices);
    return class_value;
}

void ArkWebDevicePermissionListUpdateEventStructRelease(ArkWebDevicePermissionListUpdateEvent& struct_value)
{
    ArkWebStringStructRelease(struct_value.request_id);
    ArkWebDevicePermissionDeviceIdentifierVectorStructRelease(struct_value.devices);
}

ArkWebDevicePermissionRequest ArkWebDevicePermissionRequestClassToStruct(
    const OHOS::NWeb::NWebDevicePermissionRequest& class_value)
{
    ArkWebDevicePermissionRequest struct_value;
    struct_value.request_base = ArkWebDevicePermissionRequestBaseClassToStruct(class_value.request_base);
    struct_value.request_id = ArkWebStringClassToStruct(class_value.request_id);
    struct_value.device_list = ArkWebDevicePermissionDeviceIdentifierVectorClassToStruct(
        class_value.device_list);
    return struct_value;
}

OHOS::NWeb::NWebDevicePermissionRequest ArkWebDevicePermissionRequestStructToClass(
    const ArkWebDevicePermissionRequest& struct_value)
{
    OHOS::NWeb::NWebDevicePermissionRequest class_value;
    class_value.request_base = ArkWebDevicePermissionRequestBaseStructToClass(struct_value.request_base);
    class_value.request_id = ArkWebStringStructToClass(struct_value.request_id);
    class_value.device_list = ArkWebDevicePermissionDeviceIdentifierVectorStructToClass(
        struct_value.device_list);
    return class_value;
}

void ArkWebDevicePermissionRequestStructRelease(ArkWebDevicePermissionRequest& struct_value)
{
    ArkWebDevicePermissionRequestBaseStructRelease(struct_value.request_base);
    ArkWebStringStructRelease(struct_value.request_id);
    ArkWebDevicePermissionDeviceIdentifierVectorStructRelease(struct_value.device_list);
}

} // namespace OHOS::ArkWeb
