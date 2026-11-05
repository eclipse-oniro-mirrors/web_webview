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

#include "web_device_permission_helpers.h"

#include "napi_parse_utils.h"
#include "nweb_log.h"
#include "nweb_napi_scope.h"

namespace OHOS {
namespace NWeb {

napi_value CreateStringValue(napi_env env, const std::string& str)
{
    napi_value value = nullptr;
    napi_create_string_utf8(env, str.c_str(), str.length(), &value);
    return value;
}

napi_value CreateBoolValue(napi_env env, bool b)
{
    napi_value value = nullptr;
    napi_get_boolean(env, b, &value);
    return value;
}

napi_value CreateDeviceIdentifierJsObject(napi_env env, const NWebDevicePermissionDeviceIdentifier& device)
{
    napi_value jsDevice = nullptr;
    napi_create_object(env, &jsDevice);
    napi_set_named_property(env, jsDevice, "vendorId", NapiParseUtils::ToInt32Value(env, device.vendor_id));
    napi_set_named_property(env, jsDevice, "productId", NapiParseUtils::ToInt32Value(env, device.product_id));
    napi_set_named_property(env, jsDevice, "deviceKey", CreateStringValue(env, device.device_key));
    napi_set_named_property(env, jsDevice, "deviceName", CreateStringValue(env, device.device_name));
    return jsDevice;
}

bool ParseDeviceIdentifier(napi_env env, napi_value value, NWebDevicePermissionDeviceIdentifier& device)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, value, &valueType);
    if (valueType != napi_object) {
        return false;
    }
    napi_value val = nullptr;
    int32_t number = 0;
    napi_get_named_property(env, value, "vendorId", &val);
    if (!NapiParseUtils::ParseInt32(env, val, number)) {
        return false;
    }
    device.vendor_id = number;
    napi_get_named_property(env, value, "productId", &val);
    if (!NapiParseUtils::ParseInt32(env, val, number)) {
        return false;
    }
    device.product_id = number;
    napi_get_named_property(env, value, "deviceKey", &val);
    if (!NapiParseUtils::ParseString(env, val, device.device_key)) {
        return false;
    }
    napi_get_named_property(env, value, "deviceName", &val);
    if (!NapiParseUtils::ParseString(env, val, device.device_name)) {
        return false;
    }
    return true;
}

void ParseOptionalBool(napi_env env, napi_value value, bool& out)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, value, &valueType);
    if (valueType == napi_boolean) {
        napi_get_value_bool(env, value, &out);
    }
}

bool CallJsCallback(napi_env env, napi_ref callbackRef, napi_value jsEvent)
{
    if (!env || !callbackRef || !jsEvent) {
        return false;
    }
    OHOS::NApiScope scope(env);
    napi_value callbackFunc = nullptr;
    napi_status status = napi_get_reference_value(env, callbackRef, &callbackFunc);
    if (status != napi_ok || callbackFunc == nullptr) {
        return false;
    }
    napi_value result = nullptr;
    status = napi_call_function(env, nullptr, callbackFunc, 1, &jsEvent, &result);
    return status == napi_ok;
}
} // namespace NWeb
} // namespace OHOS
