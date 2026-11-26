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

#include "napi_web_device_permission_helpers.h"

#include "napi/native_api.h"
#include "nweb_log.h"

namespace OHOS {
namespace NWeb {

napi_value NapiDevicePerm_CreateString(napi_env env, const std::string &str)
{
    napi_value value = nullptr;
    napi_create_string_utf8(env, str.c_str(), str.length(), &value);
    return value;
}

napi_value NapiDevicePerm_CreateInt32(napi_env env, int32_t num)
{
    napi_value value = nullptr;
    napi_create_int32(env, num, &value);
    return value;
}

napi_value NapiDevicePerm_CreateBool(napi_env env, bool b)
{
    napi_value value = nullptr;
    napi_get_boolean(env, b, &value);
    return value;
}

bool NapiDevicePerm_ParseDeviceIdentifier(napi_env env, napi_value value,
                                          WebDeviceIdentifier &out)
{
    if (value == nullptr) {
        return false;
    }
    napi_valuetype type = napi_undefined;
    napi_typeof(env, value, &type);
    if (type != napi_object) {
        return false;
    }
    napi_value tmp = nullptr;
    if (napi_get_named_property(env, value, "vendorId", &tmp) != napi_ok ||
        napi_get_value_int32(env, tmp, &out.vendorId) != napi_ok) {
        return false;
    }
    if (napi_get_named_property(env, value, "productId", &tmp) != napi_ok ||
        napi_get_value_int32(env, tmp, &out.productId) != napi_ok) {
        return false;
    }
    if (napi_get_named_property(env, value, "deviceKey", &tmp) != napi_ok) {
        return false;
    }
    size_t len = 0;
    if (napi_get_value_string_utf8(env, tmp, nullptr, 0, &len) != napi_ok) {
        return false;
    }
    out.deviceKey.resize(len);
    if (napi_get_value_string_utf8(env, tmp, out.deviceKey.data(), len + 1, &len) != napi_ok) {
        return false;
    }
    // deviceName is optional — default to empty string if absent.
    if (napi_get_named_property(env, value, "deviceName", &tmp) == napi_ok) {
        napi_valuetype nameType = napi_undefined;
        napi_typeof(env, tmp, &nameType);
        if (nameType != napi_undefined && nameType != napi_null) {
            size_t nameLen = 0;
            if (napi_get_value_string_utf8(env, tmp, nullptr, 0, &nameLen) == napi_ok) {
                out.deviceName.resize(nameLen);
                napi_get_value_string_utf8(env, tmp, out.deviceName.data(), nameLen + 1, &nameLen);
            }
        }
    }
    return true;
}

} // namespace NWeb
} // namespace OHOS
