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

#include "napi_geolocation_permission.h"

#include <cstdint>
#include <vector>

#include "business_error.h"
#include "nweb_napi_scope.h"
#include "napi/native_common.h"
#include "nweb_data_base.h"
#include "nweb_helper.h"
#include "web_errors.h"
#include "securec.h"

namespace {
constexpr int32_t PARAMZERO = 0;
constexpr int32_t PARAMONE = 1;
constexpr int32_t PARAMTWO = 2;
constexpr int32_t PARAMTHREE = 3;
constexpr int32_t RESULT_COUNT = 2;
constexpr int32_t INTERFACE_OK = 0;
constexpr int32_t INTERFACE_ERROR = -1;
constexpr int32_t ALLOW_PERMISSION_OPERATION = 1;
constexpr int32_t DELETE_PERMISSION_OPERATION = 2;

struct GetPermissionOriginsParam {
    std::vector<std::string> origins;
    napi_env env;
    napi_async_work asyncWork;
    napi_deferred deferred;
    napi_ref callbackRef;
    napi_status status;
    int errCode;
    bool incognitoMode;
};

struct GetOriginPermissionStateParam {
    bool retValue;
    bool incognitoMode;
    std::string origin;
    napi_env env;
    napi_async_work asyncWork;
    napi_deferred deferred;
    napi_ref jsStringRef;
    napi_ref callbackRef;
    napi_status status;
    int errCode;
};
} // namespace

namespace OHOS {
namespace NWeb {
napi_value NapiGeolocationPermission::Init(napi_env env, napi_value exports)
{
    const std::string GEOLOCATION_PERMISSION_CLASS_NAME = "GeolocationPermissions";
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_STATIC_FUNCTION("allowGeolocation", NapiGeolocationPermission::JsAllowGeolocation),
        DECLARE_NAPI_STATIC_FUNCTION("deleteGeolocation", NapiGeolocationPermission::JsDeleteGeolocation),
        DECLARE_NAPI_STATIC_FUNCTION("deleteAllGeolocation", NapiGeolocationPermission::JsDeleteAllGeolocation),
        DECLARE_NAPI_STATIC_FUNCTION("getStoredGeolocation", NapiGeolocationPermission::JsGetStoredGeolocation),
        DECLARE_NAPI_STATIC_FUNCTION("getAccessibleGeolocation",
            NapiGeolocationPermission::JsGetAccessibleGeolocation),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, GEOLOCATION_PERMISSION_CLASS_NAME.c_str(), GEOLOCATION_PERMISSION_CLASS_NAME.length(),
        JsConstructor, nullptr, sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    NAPI_ASSERT(env, constructor != nullptr, "NapiGeolocationPermission define js class failed");
    napi_status status = napi_set_named_property(env, exports, "GeolocationPermissions", constructor);
    NAPI_ASSERT(env, status == napi_ok, "NapiGeolocationPermission set property failed");
    return exports;
}

bool NapiGeolocationPermission::GetStringPara(napi_env env, napi_value argv, std::string& outValue)
{
    constexpr int32_t MAX_STRING_LENGTH = 40960;
    size_t bufferSize = 0;
    napi_valuetype valueType = napi_null;

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

bool NapiGeolocationPermission::GetBooleanPara(napi_env env, napi_value argv, bool& outValue)
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

napi_value NapiGeolocationPermission::ProcessActionByType(napi_env env, napi_callback_info info,
    int32_t operationType)
{
    napi_value retValue = nullptr;
    size_t argc = PARAMTWO;
    size_t argcForOld = PARAMONE;
    napi_value argv[PARAMTWO] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &retValue, nullptr);
    if (argc != PARAMTWO && argc != argcForOld) {
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR,
            NWebError::FormatString(ParamCheckErrorMsgTemplate::PARAM_NUMBERS_ERROR_TWO, "one", "two"));
        return nullptr;
    }

    std::string origin;
    if (!GetStringPara(env, argv[PARAMZERO], origin)) {
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR,
            NWebError::FormatString(ParamCheckErrorMsgTemplate::TYPE_ERROR, "origin", "string"));
        return nullptr;
    }
    bool incognitoMode = false;
    if (argc == PARAMTWO) {
        napi_get_value_bool(env, argv[PARAMONE], &incognitoMode);
    }

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    std::shared_ptr<OHOS::NWeb::NWebDataBase> dataBase = OHOS::NWeb::NWebHelper::Instance().GetDataBase();
    if (!dataBase) {
        return result;
    }
    if (operationType == ALLOW_PERMISSION_OPERATION) {
        if (dataBase->SetPermissionByOrigin(origin, OHOS::NWeb::NWebDataBase::WebPermissionType::GEOLOCATION_TYPE, true,
            incognitoMode) == NWebError::INVALID_ORIGIN) {
            NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::INVALID_ORIGIN);
            return result;
        }
    } else if (operationType == DELETE_PERMISSION_OPERATION) {
        if (dataBase->ClearPermissionByOrigin(origin, OHOS::NWeb::NWebDataBase::WebPermissionType::GEOLOCATION_TYPE,
            incognitoMode) == NWebError::INVALID_ORIGIN) {
            NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::INVALID_ORIGIN);
            return result;
        }
    }
    return result;
}

napi_value NapiGeolocationPermission::JsAllowGeolocation(napi_env env, napi_callback_info info)
{
    return ProcessActionByType(env, info, ALLOW_PERMISSION_OPERATION);
}

napi_value NapiGeolocationPermission::JsDeleteGeolocation(napi_env env, napi_callback_info info)
{
    return ProcessActionByType(env, info, DELETE_PERMISSION_OPERATION);
}

napi_value NapiGeolocationPermission::JsDeleteAllGeolocation(napi_env env, napi_callback_info info)
{
    napi_value retValue = nullptr;
    size_t argc = PARAMONE;
    size_t argcForOld = 0;
    napi_value argv[PARAMONE] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &retValue, nullptr);
    if (argc != PARAMONE && argc != argcForOld) {
        return nullptr;
    }
    bool incognitoMode = false;
    if (argc == PARAMONE) {
        napi_get_value_bool(env, argv[PARAMZERO], &incognitoMode);
    }

    std::shared_ptr<OHOS::NWeb::NWebDataBase> dataBase = OHOS::NWeb::NWebHelper::Instance().GetDataBase();
    if (dataBase != nullptr) {
        dataBase->ClearAllPermission(OHOS::NWeb::NWebDataBase::WebPermissionType::GEOLOCATION_TYPE, incognitoMode);
    }

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

void NapiGeolocationPermission::GetPermissionStateComplete(napi_env env, napi_status status, void *data)
{
    GetOriginPermissionStateParam *param = static_cast<GetOriginPermissionStateParam *>(data);
    NApiScope scope(env);
    if (!scope.IsVaild()) {
        return;
    }
    napi_value setResult[RESULT_COUNT] = {0};
    if (param->status) {
        setResult[PARAMZERO] = NWebError::BusinessError::CreateError(env, param->errCode);
        napi_get_undefined(env, &setResult[PARAMONE]);
    } else {
        napi_get_undefined(env, &setResult[PARAMZERO]);
        napi_get_boolean(env, param->retValue, &setResult[PARAMONE]);
    }
    napi_value args[RESULT_COUNT] = {setResult[PARAMZERO], setResult[PARAMONE]};
    napi_value callback = nullptr;
    napi_get_reference_value(env, param->callbackRef, &callback);
    napi_value returnVal = nullptr;
    napi_call_function(env, nullptr, callback, RESULT_COUNT, args, &returnVal);
    napi_delete_reference(env, param->jsStringRef);
    napi_delete_reference(env, param->callbackRef);
    napi_delete_async_work(env, param->asyncWork);
    delete param;
    param = nullptr;
}

void NapiGeolocationPermission::GetPermissionStatePromiseComplete(napi_env env, napi_status status, void *data)
{
    GetOriginPermissionStateParam *param = static_cast<GetOriginPermissionStateParam *>(data);
    NApiScope scope(env);
    if (!scope.IsVaild()) {
        return;
    }
    napi_value setResult[RESULT_COUNT] = {0};
    setResult[PARAMZERO] = NWebError::BusinessError::CreateError(env, param->errCode);
    napi_get_boolean(env, param->retValue, &setResult[PARAMONE]);
    napi_value args[RESULT_COUNT] = {setResult[PARAMZERO], setResult[PARAMONE]};
    if (param->status == napi_ok) {
        napi_resolve_deferred(env, param->deferred, args[1]);
    } else {
        napi_reject_deferred(env, param->deferred, args[0]);
    }
    napi_delete_reference(env, param->jsStringRef);
    napi_delete_async_work(env, param->asyncWork);
    delete param;
    param = nullptr;
}

void NapiGeolocationPermission::ExecuteGetPermissionState(napi_env env, void *data)
{
    GetOriginPermissionStateParam *param = static_cast<GetOriginPermissionStateParam *>(data);
    std::shared_ptr<OHOS::NWeb::NWebDataBase> dataBase = OHOS::NWeb::NWebHelper::Instance().GetDataBase();
    if (!dataBase) {
        param->errCode = INTERFACE_ERROR;
        param->status = napi_generic_failure;
        return;
    }
    if (dataBase->GetPermissionResultByOrigin(param->origin,
        OHOS::NWeb::NWebDataBase::WebPermissionType::GEOLOCATION_TYPE, param->retValue, param->incognitoMode)) {
        param->errCode = INTERFACE_OK;
        param->status = napi_ok;
    } else {
        param->errCode = NWebError::INVALID_ORIGIN;
        param->status = napi_generic_failure;
    }
}

napi_value NapiGeolocationPermission::GetPermissionStateAsync(napi_env env,
    napi_value *argv, const std::string& origin, bool incognitoMode)
{
    napi_value result = nullptr;
    napi_value resourceName = nullptr;

    GetOriginPermissionStateParam *param = new (std::nothrow) GetOriginPermissionStateParam {
        .retValue = false,
        .incognitoMode = incognitoMode,
        .origin = origin,
        .env = env,
        .asyncWork = nullptr,
        .deferred = nullptr,
        .jsStringRef = nullptr,
        .callbackRef = nullptr,
    };
    if (param == nullptr) {
        return nullptr;
    }
    napi_create_reference(env, argv[0], 1, &param->jsStringRef);
    napi_create_reference(env, argv[1], 1, &param->callbackRef);
    NAPI_CALL(env, napi_create_string_utf8(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName, ExecuteGetPermissionState,
        GetPermissionStateComplete, static_cast<void *>(param), &param->asyncWork));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, param->asyncWork, napi_qos_user_initiated));
    napi_get_undefined(env, &result);
    return result;
}

napi_value NapiGeolocationPermission::GetPermissionStatePromise(napi_env env, napi_value *argv,
    const std::string& origin, bool incognitoMode)
{
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_create_promise(env, &deferred, &promise);

    GetOriginPermissionStateParam *param = new (std::nothrow) GetOriginPermissionStateParam {
        .retValue = false,
        .incognitoMode = incognitoMode,
        .origin = origin,
        .env = env,
        .asyncWork = nullptr,
        .deferred = deferred,
        .jsStringRef = nullptr,
        .callbackRef = nullptr,
    };
    if (param == nullptr) {
        return nullptr;
    }
    napi_create_reference(env, argv[0], 1, &param->jsStringRef);
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName, ExecuteGetPermissionState,
        GetPermissionStatePromiseComplete, static_cast<void *>(param), &param->asyncWork));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, param->asyncWork, napi_qos_user_initiated));
    return promise;
}

napi_value NapiGeolocationPermission::JsGetAccessibleGeolocation(napi_env env, napi_callback_info info)
{
    napi_value retValue = nullptr;
    size_t argc = PARAMTHREE;
    size_t argcPromiseForOld = PARAMONE;
    size_t argcPromise = PARAMTWO;
    size_t argcCallback = PARAMTHREE;
    napi_value argv[PARAMTHREE] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &retValue, nullptr);
    if (argc != argcPromise && argc != argcCallback && argc != argcPromiseForOld) {
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR, 
            NWebError::FormatString(ParamCheckErrorMsgTemplate::PARAM_NUMBERS_ERROR_THREE, "one", "two", "three"));
        return nullptr;
    }
    std::string origin;
    if (!GetStringPara(env, argv[PARAMZERO], origin)) {
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR, 
            NWebError::FormatString(ParamCheckErrorMsgTemplate::TYPE_ERROR, "origin", "string"));
        return nullptr;
    }
    bool incognitoMode = false;
    napi_value result = nullptr;
    if (argc == argcCallback) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[PARAMONE], &valueType);
        if (valueType != napi_function) {
            NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR, 
                NWebError::FormatString(ParamCheckErrorMsgTemplate::TYPE_ERROR, "callback", "function"));
            return nullptr;
        }
        if (!GetBooleanPara(env, argv[PARAMTWO], incognitoMode)) {
            NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR, 
                NWebError::FormatString(ParamCheckErrorMsgTemplate::TYPE_ERROR, "incognito", "boolean"));
            return nullptr;
        }
        GetPermissionStateAsync(env, argv, origin, incognitoMode);
        napi_get_undefined(env, &result);
        return result;
    }
    if (argc == PARAMTWO) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[PARAMONE], &valueType);
        if (valueType != napi_function) {
            if (!GetBooleanPara(env, argv[PARAMONE], incognitoMode)) {
                NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR, 
                    NWebError::FormatString(ParamCheckErrorMsgTemplate::TYPE_ERROR, "incognito", "boolean"));
                return nullptr;
            }
            return GetPermissionStatePromise(env, argv, origin, incognitoMode);
        }
        GetPermissionStateAsync(env, argv, origin, incognitoMode);
        napi_get_undefined(env, &result);
        return result;
    }
    return GetPermissionStatePromise(env, argv, origin, incognitoMode);
}

void NapiGeolocationPermission::GetOriginComplete(napi_env env, napi_status status, void *data)
{
    GetPermissionOriginsParam *param = static_cast<GetPermissionOriginsParam *>(data);
    NApiScope scope(env);
    if (!scope.IsVaild()) {
        return;
    }
    napi_value setResult[RESULT_COUNT] = {0};
    if (param->status) {
        napi_get_undefined(env, &setResult[PARAMZERO]);
        napi_get_undefined(env, &setResult[PARAMONE]);
    } else {
        napi_get_undefined(env, &setResult[PARAMZERO]);
        napi_create_array(env, &setResult[PARAMONE]);
        for (uint32_t i = 0; i < param->origins.size(); i++) {
            std::string str = param->origins[i];
            napi_value val = nullptr;
            napi_create_string_utf8(env, str.c_str(), str.length(), &val);
            napi_set_element(env, setResult[PARAMONE], i, val);
        }
    }
    napi_value args[RESULT_COUNT] = {setResult[PARAMZERO], setResult[PARAMONE]};
    napi_value callback = nullptr;
    napi_get_reference_value(env, param->callbackRef, &callback);
    napi_value returnVal = nullptr;
    napi_call_function(env, nullptr, callback, RESULT_COUNT, args, &returnVal);
    napi_delete_reference(env, param->callbackRef);
    napi_delete_async_work(env, param->asyncWork);
    delete param;
    param = nullptr;
}

void NapiGeolocationPermission::GetOriginsPromiseComplete(napi_env env, napi_status status, void *data)
{
    GetPermissionOriginsParam *param = static_cast<GetPermissionOriginsParam *>(data);
    NApiScope scope(env);
    if (!scope.IsVaild()) {
        delete param;
        return;
    }
    napi_value setResult[RESULT_COUNT] = {0};
    napi_get_undefined(env, &setResult[PARAMZERO]);
    napi_create_array(env, &setResult[PARAMONE]);
    for (uint32_t i = 0; i < param->origins.size(); i++) {
        std::string str = param->origins[i];
        napi_value val = nullptr;
        napi_create_string_utf8(env, str.c_str(), str.length(), &val);
        napi_set_element(env, setResult[PARAMONE], i, val);
    }
    napi_value args[RESULT_COUNT] = {setResult[PARAMZERO], setResult[PARAMONE]};
    if (param->status == napi_ok) {
        napi_resolve_deferred(env, param->deferred, args[1]);
    } else {
        napi_reject_deferred(env, param->deferred, args[0]);
    }
    napi_delete_async_work(env, param->asyncWork);
    delete param;
    param = nullptr;
}

void NapiGeolocationPermission::ExecuteGetOrigins(napi_env env, void *data)
{
    GetPermissionOriginsParam *param = static_cast<GetPermissionOriginsParam *>(data);
    std::shared_ptr<OHOS::NWeb::NWebDataBase> dataBase = OHOS::NWeb::NWebHelper::Instance().GetDataBase();
    if (!dataBase) {
        param->errCode = INTERFACE_ERROR;
        param->status = napi_generic_failure;
        return;
    }
    param->origins = dataBase->GetOriginsByPermission(
        OHOS::NWeb::NWebDataBase::WebPermissionType::GEOLOCATION_TYPE, param->incognitoMode);
    param->errCode = INTERFACE_OK;
    param->status = napi_ok;
}

napi_value NapiGeolocationPermission::GetOriginsAsync(napi_env env,
                                                      napi_value *argv,
                                                      bool incognitoMode)
{
    napi_value result = nullptr;
    napi_value resourceName = nullptr;

    GetPermissionOriginsParam *param = new (std::nothrow) GetPermissionOriginsParam {
        .env = env,
        .asyncWork = nullptr,
        .deferred = nullptr,
        .callbackRef = nullptr,
        .incognitoMode = incognitoMode,
    };
    if (param == nullptr) {
        return nullptr;
    }
    napi_create_reference(env, *argv, 1, &param->callbackRef);
    NAPI_CALL(env, napi_create_string_utf8(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName, ExecuteGetOrigins,
        GetOriginComplete, static_cast<void *>(param), &param->asyncWork));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, param->asyncWork, napi_qos_user_initiated));
    napi_get_undefined(env, &result);
    return result;
}

napi_value NapiGeolocationPermission::GetOriginsPromise(napi_env env,
                                                        bool incognitoMode)
{
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_create_promise(env, &deferred, &promise);

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    GetPermissionOriginsParam *param = new (std::nothrow) GetPermissionOriginsParam {
        .env = env,
        .asyncWork = nullptr,
        .deferred = deferred,
        .callbackRef = nullptr,
        .incognitoMode = incognitoMode,
    };
    if (param == nullptr) {
        return nullptr;
    }
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName, ExecuteGetOrigins,
        GetOriginsPromiseComplete, static_cast<void *>(param), &param->asyncWork));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, param->asyncWork, napi_qos_user_initiated));
    return promise;
}

napi_value NapiGeolocationPermission::JsGetStoredGeolocation(napi_env env, napi_callback_info info)
{
    napi_value retValue = nullptr;
    size_t argc = PARAMTWO;
    size_t argcForZero = PARAMZERO;
    size_t argcPromise = PARAMONE;
    size_t argcCallback = PARAMTWO;
    napi_value argv[PARAMTWO] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &retValue, nullptr);
    if (argc != argcPromise && argc != argcCallback && argc != argcForZero) {
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR,
            NWebError::FormatString(ParamCheckErrorMsgTemplate::PARAM_NUMBERS_ERROR_THREE, "one", "two", "three"));
        return nullptr;
    }

    bool incognitoMode = false;
    if (argc == argcCallback) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[PARAMZERO], &valueType);
        if (valueType != napi_function) {
            NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR,
                NWebError::FormatString(ParamCheckErrorMsgTemplate::TYPE_ERROR, "callback", "function"));
            return nullptr;
        }

        if (!GetBooleanPara(env, argv[PARAMONE], incognitoMode)) {
            NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR,
                NWebError::FormatString(ParamCheckErrorMsgTemplate::TYPE_ERROR, "incognito", "boolean"));
            return nullptr;
        }
        GetOriginsAsync(env, argv, incognitoMode);
        napi_value result = nullptr;
        napi_get_undefined(env, &result);
        return result;
    }

    if (argc == PARAMONE) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[PARAMZERO], &valueType);
        if (valueType != napi_function) {
            if (!GetBooleanPara(env, argv[PARAMZERO], incognitoMode)) {
                NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR,
                    NWebError::FormatString(ParamCheckErrorMsgTemplate::TYPE_ERROR, "incognito", "boolean"));
                return nullptr;
            }
            return GetOriginsPromise(env, incognitoMode);
        }
        GetOriginsAsync(env, argv, incognitoMode);
        napi_value result = nullptr;
        napi_get_undefined(env, &result);
        return result;
    }

    return GetOriginsPromise(env, incognitoMode);
}

napi_value NapiGeolocationPermission::JsConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = PARAMTWO;
    napi_value argv[PARAMTWO] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    return thisVar;
}
} // namespace NWeb
} // namespace OHOS
