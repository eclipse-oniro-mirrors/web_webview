/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef NAPI_WEB_DEVICE_PERMISSION_HELPERS_H
#define NAPI_WEB_DEVICE_PERMISSION_HELPERS_H

#include <cstddef>
#include <cstdint>
#include <string>

#include "napi/native_api.h"
#include "web_device_permission_request.h"

namespace OHOS {
namespace NWeb {

// Shared interface limits for the device permission NAPI bindings.
constexpr size_t DEVICE_PERM_MAX_PERMISSION_LIST_SIZE = 1024;
constexpr size_t DEVICE_PERM_MAX_SITE_POLICIES_SIZE = 256;
constexpr size_t DEVICE_PERM_MAX_ORIGIN_LENGTH = 512;
constexpr size_t DEVICE_PERM_MAX_DEVICE_KEY_LENGTH = 256;
constexpr int32_t DEVICE_PERM_MAX_DEVICE_ID = 65535;
constexpr int32_t DEVICE_PERM_MAX_HARDWARE_TYPE = 3;
constexpr size_t DEVICE_PERM_HARDWARE_TYPE_COUNT = 4;
constexpr int32_t DEVICE_PERM_MAX_GUARD_POLICY = 2;

// Shared NAPI helper functions used by both napi_web_device_permission_callback.cpp
// and napi_web_device_permission_request.cpp.

napi_value NapiDevicePerm_CreateString(napi_env env, const std::string &str);
napi_value NapiDevicePerm_CreateInt32(napi_env env, int32_t num);
napi_value NapiDevicePerm_CreateBool(napi_env env, bool b);

// Reads vendorId, productId, deviceKey, deviceName from a JS object into the
// given WebDeviceIdentifier. Returns false on any parse failure.
bool NapiDevicePerm_ParseDeviceIdentifier(napi_env env, napi_value value,
                                          WebDeviceIdentifier &out);

} // namespace NWeb
} // namespace OHOS

#endif // NAPI_WEB_DEVICE_PERMISSION_HELPERS_H
