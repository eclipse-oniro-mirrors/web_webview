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

#include "napi_web_cookie_manager.h"

#include <cstdint>
#include <vector>

#include "napi/native_common.h"
#include "nweb_cookie_manager.h"
#include "nweb_helper.h"
#include "securec.h"

namespace OHOS {
napi_value NapiWebCookieManager::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_STATIC_FUNCTION("getCookie", NapiWebCookieManager::JsGetCookie),
    };
    napi_value constructor = nullptr;

    napi_define_class(env, WEB_COOKIE_MANAGER_CLASS_NAME.c_str(), WEB_COOKIE_MANAGER_CLASS_NAME.length(),
        JsConstructor, nullptr, sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    NAPI_ASSERT(env, constructor != nullptr, "NapiWebCookieManager define js class failed");
    napi_status status = napi_set_named_property(env, exports, "WebCookieManager", constructor);
    NAPI_ASSERT(env, status == napi_ok, "NapiWebCookieManager set property failed");
    return exports;
}

napi_value NapiWebCookieManager::JsConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = 2;
    napi_value argv[2] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    return thisVar;
}

constexpr int MAX_STRING_LENGTH = 40960;
bool GetStringPara(napi_env env, napi_value argv, std::string& outValue)
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

napi_value NapiWebCookieManager::JsGetCookie(napi_env env, napi_callback_info info)
{
    napi_value retValue = nullptr;
    size_t argc = 1;
    napi_value argv[1] = { 0 };

    napi_get_cb_info(env, info, &argc, argv, &retValue, nullptr);
    NAPI_ASSERT(env, argc == 1, "requires 1 parameter");

    bool ret;
    std::string url;
    ret = GetStringPara(env, argv[0], url);
    NAPI_ASSERT_BASE(env, ret, "get para0 failed", retValue);

    napi_value result = nullptr;
    std::string cookieContent = "";

    OHOS::NWeb::NWebCookieManager* cookieManager = OHOS::NWeb::NWebHelper::Instance().GetCookieManager();
    if (cookieManager != nullptr) {
        cookieContent = cookieManager->ReturnCookie(url);
    }
    napi_create_string_utf8(env, cookieContent.c_str(), cookieContent.length(), &result);
    return result;
}
} // namespace OHOS