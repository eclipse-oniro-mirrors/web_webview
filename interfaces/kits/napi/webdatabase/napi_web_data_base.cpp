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

#include "napi_web_data_base.h"
#include <unistd.h>
#include <vector>

#include "nweb_data_base.h"
#include "nweb_helper.h"
#include "securec.h"

namespace OHOS {
napi_value NapiWebDataBase::Init(napi_env env, napi_value exports)
{
    const std::string WEB_DATA_BASE_CLASS_NAME = "WebDataBase";
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_STATIC_FUNCTION("deleteHttpAuthCredentials", NapiWebDataBase::JsDeleteHttpAuthCredentials),
        DECLARE_NAPI_STATIC_FUNCTION("saveHttpAuthCredentials", NapiWebDataBase::JsSaveHttpAuthCredentials),
        DECLARE_NAPI_STATIC_FUNCTION("getHttpAuthCredentials", NapiWebDataBase::JsGetHttpAuthCredentials),
        DECLARE_NAPI_STATIC_FUNCTION("existHttpAuthCredentials", NapiWebDataBase::JsExistHttpAuthCredentials),
    };
    napi_value constructor = nullptr;

    napi_define_class(env, WEB_DATA_BASE_CLASS_NAME.c_str(), WEB_DATA_BASE_CLASS_NAME.length(), JsConstructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    NAPI_ASSERT(env, constructor != nullptr, "NapiWebDataBase define js class failed");
    napi_status status = napi_set_named_property(env, exports, "WebDataBase", constructor);
    NAPI_ASSERT(env, status == napi_ok, "NapiWebDataBase set property failed");
    return exports;
}

napi_value NapiWebDataBase::JsDeleteHttpAuthCredentials(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    OHOS::NWeb::NWebDataBase* dataBase = OHOS::NWeb::NWebHelper::Instance().GetDataBase();
    if (dataBase != nullptr) {
        dataBase->ClearHttpAuthUsernamePassword();
    }
    napi_get_undefined(env, &result);
    return result;
}

napi_value NapiWebDataBase::JsExistHttpAuthCredentials(napi_env env, napi_callback_info info)
{
    bool isExist = false;
    napi_value result = nullptr;

    OHOS::NWeb::NWebDataBase* dataBase = OHOS::NWeb::NWebHelper::Instance().GetDataBase();
    if (dataBase != nullptr) {
        isExist = dataBase->ExistHttpAuthUsernamePassword();
    }
    NAPI_CALL(env, napi_get_boolean(env, isExist, &result));
    return result;
}

bool NapiWebDataBase::GetStringPara(napi_env env, napi_value argv, std::string& outValue)
{
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

napi_value NapiWebDataBase::JsSaveHttpAuthCredentials(napi_env env, napi_callback_info info)
{
    napi_value retValue = nullptr;
    size_t argc = 4;
    napi_value argv[4] = { 0 };
    
    napi_get_cb_info(env, info, &argc, argv, &retValue, nullptr);
    NAPI_ASSERT(env, argc == 4, "requires 4 parameter");

    bool ret;
    std::string host;
    ret = GetStringPara(env, argv[0], host);
    NAPI_ASSERT_BASE(env, ret, "get para0 failed", retValue);

    std::string realm;
    ret = GetStringPara(env, argv[1], realm);
    NAPI_ASSERT_BASE(env, ret, "get para1 failed", retValue);

    std::string username;
    ret = GetStringPara(env, argv[2], username);
    NAPI_ASSERT_BASE(env, ret, "get para2 failed", retValue);

    std::string password;
    ret = GetStringPara(env, argv[3], password);
    NAPI_ASSERT_BASE(env, ret, "get para3 failed", retValue);

    OHOS::NWeb::NWebDataBase* dataBase = OHOS::NWeb::NWebHelper::Instance().GetDataBase();
    if (dataBase != nullptr) {
        dataBase->SaveHttpAuthUsernamePassword(host, realm, username, password);
    }

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value NapiWebDataBase::JsGetHttpAuthCredentials(napi_env env, napi_callback_info info)
{
    napi_value retValue = nullptr;
    size_t argc = 2;
    napi_value argv[2] = { 0 };

    napi_get_cb_info(env, info, &argc, argv, &retValue, nullptr);
    NAPI_ASSERT(env, argc == 2, "requires 2 parameter");

    bool ret;
    std::string host;
    ret = GetStringPara(env, argv[0], host);
    NAPI_ASSERT_BASE(env, ret, "get para0 failed", retValue);

    std::string realm;
    ret = GetStringPara(env, argv[1], realm);
    NAPI_ASSERT_BASE(env, ret, "get para1 failed", retValue);

    std::vector<std::string> usernamePassword;
    napi_value result = nullptr;
    napi_create_array(env, &result);

    OHOS::NWeb::NWebDataBase* dataBase = OHOS::NWeb::NWebHelper::Instance().GetDataBase();
    if (dataBase != nullptr) {
        usernamePassword = dataBase->GetHttpAuthUsernamePassword(host, realm);
    }
    for (uint32_t i = 0; i < usernamePassword.size(); i++) {
        std::string str = usernamePassword[i];
        napi_value val = nullptr;
        napi_create_string_utf8(env, str.c_str(), str.length(), &val);
        napi_set_element(env, result, i, val);
    }
    return result;
}

napi_value NapiWebDataBase::JsConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = 2;
    napi_value argv[2] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    return thisVar;
}
} // namespace OHOS