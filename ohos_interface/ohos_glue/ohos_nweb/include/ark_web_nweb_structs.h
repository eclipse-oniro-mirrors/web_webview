/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef ARK_WEB_NWEB_STRUCTS_H
#define ARK_WEB_NWEB_STRUCTS_H

#include <stdint.h>
#include <functional>
#include "base/include/ark_web_types.h"

#include "base/include/ark_web_types.h"

typedef struct {
    int32_t year;
    int32_t month;
    int32_t day;
    int32_t hour;
    int32_t minute;
    int32_t second;
} ArkWebDateTime;

const ArkWebDateTime ark_web_date_time_default = {
    0,
};

typedef int64_t (*AccessibilityIdGenerateFunc)();

typedef void (*NativeArkWebOnValidCallback)(const char*);

typedef void (*NativeArkWebOnDestroyCallback)(const char*);

typedef char* (*NativeArkWebOnJavaScriptProxyCallback)(const char**, int32_t);

using WebSnapshotCallback = std::function<void(const char*, bool, float, void*, int, int)>;

typedef struct {
    int32_t vendor_id;
    int32_t product_id;
    ArkWebString device_key;
    ArkWebString device_name;
} ArkWebDevicePermissionDeviceIdentifier;

const ArkWebDevicePermissionDeviceIdentifier ark_web_device_permission_device_identifier_default = {
    0,
};

typedef struct {
    int size;
    ArkWebDevicePermissionDeviceIdentifier* value;

    ArkWebMemFreeFunc ark_web_mem_free_func;
} ArkWebDevicePermissionDeviceIdentifierVector;

const ArkWebDevicePermissionDeviceIdentifierVector
    ark_web_device_permission_device_identifier_vector_default = {
    0,
};

typedef struct {
    int32_t hardware_type;
    ArkWebString origin;
    bool is_incognito;
} ArkWebDevicePermissionRequestBase;

const ArkWebDevicePermissionRequestBase ark_web_device_permission_request_base_default = {
    0,
};

typedef struct {
    int32_t hardware_type;
    ArkWebString origin;
    bool is_incognito;
    ArkWebDevicePermissionDeviceIdentifier device;
} ArkWebDevicePermissionRevokedEvent;

const ArkWebDevicePermissionRevokedEvent ark_web_device_permission_revoked_event_default = {
    0,
};

typedef struct {
    ArkWebString request_id;
    int32_t action;
    ArkWebDevicePermissionDeviceIdentifierVector devices;
} ArkWebDeviceListUpdateEvent;

const ArkWebDeviceListUpdateEvent ark_web_device_list_update_event_default = {};

#endif // ARK_WEB_NWEB_STRUCTS_H