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

#include "napi_parse_utils.h"
#include "nweb_log.h"

namespace {
constexpr int MAX_STRING_LENGTH = 40960;
}

namespace OHOS {
namespace NWeb {
napi_value NapiParseUtils::CreateEnumConstructor(napi_env env, napi_callback_info info)
{
    napi_value arg = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &arg, nullptr);
    return arg;
}

napi_value NapiParseUtils::ToInt32Value(napi_env env, int32_t number)
{
    napi_value result = nullptr;
    napi_create_int32(env, number, &result);
    return result;
}

bool NapiParseUtils::ParseInt32(napi_env env, napi_value argv, int32_t& outValue)
{
    napi_valuetype valueType = napi_undefined;

    napi_typeof(env, argv, &valueType);
    if (valueType != napi_number) {
        return false;
    }

    int32_t number = 0;
    napi_get_value_int32(env, argv, &number);
    outValue = number;

    return true;
}

bool NapiParseUtils::ParseInt64(napi_env env, napi_value argv, int64_t& outValue)
{
    napi_valuetype valueType = napi_undefined;

    napi_typeof(env, argv, &valueType);
    if (valueType != napi_number) {
        return false;
    }

    int64_t number = 0;
    napi_get_value_int64(env, argv, &number);
    outValue = number;

    return true;
}

bool NapiParseUtils::ParseString(napi_env env, napi_value argv, std::string& outValue)
{
    size_t bufferSize = 0;
    napi_valuetype valueType = napi_undefined;

    napi_typeof(env, argv, &valueType);
    if (valueType != napi_string) {
        return false;
    }
    napi_get_value_string_utf8(env, argv, nullptr, 0, &bufferSize);
    if (bufferSize > MAX_STRING_LENGTH) {
        return false;
    }
    char stringValue[bufferSize + 1];
    size_t jsStringLength = 0;
    napi_get_value_string_utf8(env, argv, stringValue, bufferSize + 1, &jsStringLength);
    if (jsStringLength != bufferSize) {
        return false;
    }
    outValue = stringValue;
    return true;
}

bool NapiParseUtils::ParseBoolean(napi_env env, napi_value argv, bool& outValue)
{
    napi_valuetype valueType = napi_null;

    napi_typeof(env, argv, &valueType);
    if (valueType != napi_boolean) {
        return false;
    }

    bool boolValue;
    napi_get_value_bool(env, argv, &boolValue);
    outValue = boolValue;
    return true;
}

bool NapiParseUtils::ParseStringArray(napi_env env, napi_value argv, std::vector<std::string>& outValue)
{
    bool isArray = false;
    napi_is_array(env, argv, &isArray);
    if (!isArray) {
        return false;
    }

    uint32_t arrLen = 0;
    napi_get_array_length(env, argv, &arrLen);
    for (uint32_t i = 0; i < arrLen; ++i) {
        napi_value item = nullptr;
        napi_get_element(env, argv, i, &item);

        std::string str;
        if (ParseString(env, item, str)) {
            outValue.push_back(str);
        }
    }

    return true;
}

bool NapiParseUtils::ParseInt64Array(napi_env env, napi_value argv, std::vector<int64_t>& outValue)
{
    bool isArray = false;
    napi_is_array(env, argv, &isArray);
    if (!isArray) {
        return false;
    }

    uint32_t arrLen = 0;
    napi_get_array_length(env, argv, &arrLen);
    for (uint32_t i = 0; i < arrLen; ++i) {
        napi_value item = nullptr;
        napi_get_element(env, argv, i, &item);

        int64_t value;
        if (ParseInt64(env, item, value)) {
            outValue.push_back(value);
        }
    }

    return true;
}

bool NapiParseUtils::ParseBooleanArray(napi_env env, napi_value argv, std::vector<bool>& outValue)
{
    bool isArray = false;
    napi_is_array(env, argv, &isArray);
    if (!isArray) {
        return false;
    }

    uint32_t arrLen = 0;
    napi_get_array_length(env, argv, &arrLen);
    for (uint32_t i = 0; i < arrLen; ++i) {
        napi_value item = nullptr;
        napi_get_element(env, argv, i, &item);

        bool value;
        if (ParseBoolean(env, item, value)) {
            outValue.push_back(value);
        }
    }

    return true;
}

bool NapiParseUtils::ParseDoubleArray(napi_env env, napi_value argv, std::vector<double>& outValue)
{
    bool isArray = false;
    napi_is_array(env, argv, &isArray);
    if (!isArray) {
        return false;
    }

    uint32_t arrLen = 0;
    napi_get_array_length(env, argv, &arrLen);
    for (uint32_t i = 0; i < arrLen; ++i) {
        napi_value item = nullptr;
        napi_get_element(env, argv, i, &item);

        double value;
        if (ParseDouble(env, item, value)) {
            outValue.push_back(value);
        }
    }

    return true;
}

bool NapiParseUtils::ParseFloat(napi_env env, napi_value argv, float& outValue)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv, &valueType);
    if (valueType != napi_number) {
        return false;
    }

    double value;
    napi_get_value_double(env, argv, &value);
    outValue = static_cast<float>(value);
    return true;
}

bool NapiParseUtils::ParseDouble(napi_env env, napi_value argv, double& outValue)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv, &valueType);
    if (valueType != napi_number) {
        return false;
    }

    double value;
    napi_get_value_double(env, argv, &value);
    outValue = value;
    return true;
}

//static
bool NapiParseUtils::ConvertNWebToNapiValue(napi_env env, std::shared_ptr<NWebMessage> src, napi_value& dst) {
    NWebValue::Type type = src->GetType();
    switch (type) {
        case NWebValue::Type::STRING: {
            std::string msgStr = src->GetString();
            napi_create_string_utf8(env, msgStr.c_str(), msgStr.length(), &dst);
            break;
        }
        case NWebValue::Type::BINARY: {
            std::vector<uint8_t> msgArr = src->GetBinary();
            void *arrayData = nullptr;
            napi_create_arraybuffer(env, msgArr.size(), &arrayData, &dst);
            if (arrayData == nullptr) {
                WVLOG_E("Create arraybuffer failed");
                return false;
            }
            for (int i = 0; i < msgArr.size(); ++i) {
                *(uint8_t*)((uint8_t*)arrayData + i) = msgArr[i];
            }
            break;
        }
        case NWebValue::Type::BOOLEAN: {
            bool value = src->GetBoolean();
            napi_get_boolean(env, value, &dst);
            break;
        }
        case NWebValue::Type::INTEGER: {
            int64_t value = src->GetInt64();
            napi_create_int64(env, value, &dst);
            break;
        }
        case NWebValue::Type::DOUBLE: {
            double value = src->GetDouble();
            napi_create_double(env, value, &dst);
            break;
        }
        case NWebValue::Type::ERROR: {
            std::string errorName = src->GetErrName();
            std::string errorMsg = src->GetErrName() + ": " + src->GetErrMsg();
            napi_value name = nullptr;
            napi_value message = nullptr;
            napi_create_string_utf8(env, errorName.c_str(), errorName.length(), &name);
            napi_create_string_utf8(env, errorMsg.c_str(), errorMsg.length(), &message);
            napi_create_error(env, name, message, &dst);
            break;
        }
        case NWebValue::Type::STRINGARRAY: {
            std::vector<std::string> values = src->GetStringArray();
            napi_create_array(env, &dst);
            bool isArray = false;
            if (napi_is_array(env, dst, &isArray) != napi_ok || !isArray) {
                WVLOG_E("Create array failed");
                return false;
            }

            int32_t index = 0;
            for (auto value : values) {
                napi_value element = nullptr;
                napi_create_string_utf8(env, value.c_str(), value.length(), &element);
                napi_set_element(env, dst, index++, element);
            }
            break;
        }
        case NWebValue::Type::BOOLEANARRAY: {
            std::vector<bool> values = src->GetBooleanArray();
            napi_create_array(env, &dst);
            bool isArray = false;
            if (napi_is_array(env, dst, &isArray) != napi_ok || !isArray) {
                WVLOG_E("Create array failed");
                return false;
            }

            int32_t index = 0;
            for (auto value : values) {
                napi_value element = nullptr;
                napi_get_boolean(env, value, &element);
                napi_set_element(env, dst, index++, element);
            }
            break;
        }
        case NWebValue::Type::DOUBLEARRAY: {
            std::vector<double> values = src->GetDoubleArray();
            napi_create_array(env, &dst);
            bool isArray = false;
            if (napi_is_array(env, dst, &isArray) != napi_ok || !isArray) {
                WVLOG_E("Create array failed");
                return false;
            }

            int32_t index = 0;
            for (auto value : values) {
                napi_value element = nullptr;
                napi_create_double(env, value, &element);
                napi_set_element(env, dst, index++, element);
            }
                break;
            }
        case NWebValue::Type::INT64ARRAY: {
            std::vector<int64_t> values = src->GetInt64Array();
            napi_create_array(env, &dst);
            bool isArray = false;
            if (napi_is_array(env, dst, &isArray) != napi_ok || !isArray) {
                WVLOG_E("Create array failed");
                return false;
            }

            int32_t index = 0;
            for (auto value : values) {
                napi_value element = nullptr;
                napi_create_int64(env, value, &element);
                napi_set_element(env, dst, index++, element);
            }
                break;
            }
        default: {
            WVLOG_E("This type not support");
            std::string msgStr = "This type not support";
            napi_create_string_utf8(env, msgStr.c_str(), msgStr.length(), &dst);
            break;
        }
    }
    return true;
}
} // namespace NWeb
} // namespace OHOS