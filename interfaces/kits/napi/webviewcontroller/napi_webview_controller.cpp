/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "napi_webview_controller.h"
#include "nweb.h"
#include "nweb_helper.h"
#include "nweb_store_web_archive_callback.h"
#include "nweb_log.h"

namespace OHOS {
NapiWebviewController::NapiWebviewController(napi_env env, napi_value thisVar, int32_t webId) : nwebId(webId) {}

napi_value NapiWebviewController::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("setWebId", NapiWebviewController::JsSetWebId),
        DECLARE_NAPI_FUNCTION("accessForward", NapiWebviewController::JsAccessForward),
        DECLARE_NAPI_FUNCTION("accessBackward", NapiWebviewController::JsAccessBackward),
        DECLARE_NAPI_FUNCTION("forward", NapiWebviewController::JsForward),
        DECLARE_NAPI_FUNCTION("backward", NapiWebviewController::JsBackward),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, WEBVIEW_CONTROLLER_CLASS_NAME.c_str(), WEBVIEW_CONTROLLER_CLASS_NAME.length(),
        JsConstructor, nullptr, sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    NAPI_ASSERT(env, constructor != nullptr, "define js class WebviewController failed");
    napi_status status = napi_set_named_property(env, exports, "WebviewController", constructor);
    NAPI_ASSERT(env, status == napi_ok, "set property WebviewController failed");
    return exports;
}

napi_value NapiWebviewController::JsConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = 2;
    napi_value argv[2] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);

    return thisVar;
}

napi_value NapiWebviewController::JsSetWebId(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    void* data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

    int32_t webId = -1;
    if (!GetIntPara(env, argv[0], webId)) {
        return nullptr;
    }
    NapiWebviewController *webviewController = new NapiWebviewController(env, thisVar, webId);
    napi_status status = napi_wrap(
        env, thisVar, webviewController,
        [](napi_env env, void *data, void *hint) {
            NapiWebviewController *webviewController = static_cast<NapiWebviewController *>(data);
            delete webviewController;
        },
        nullptr, nullptr);
    if (status != napi_ok) {
        return nullptr;
    }
    
    return thisVar;
}

bool NapiWebviewController::GetIntPara(napi_env env, napi_value argv, int32_t& outValue)
{
    napi_valuetype valueType = napi_null;

    napi_typeof(env, argv, &valueType);
    if (valueType != napi_number) {
        return false;
    }

    int32_t number = 0;
    napi_get_value_int32(env, argv, &number);
    outValue = number;

    return true;
}

constexpr int MAX_STRING_LENGTH = 40960;
bool NapiWebviewController::GetStringPara(napi_env env, napi_value argv, std::string& outValue)
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

napi_value NapiWebviewController::JsAccessForward(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_value result = nullptr;

    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiWebviewController *webviewController = nullptr;
    napi_unwrap(env, thisVar, (void **)&webviewController);

    if (!webviewController) {
        return result;
    }
    bool access = webviewController->JsAccessForwardInternal(env, info);

    NAPI_CALL(env, napi_get_boolean(env, access, &result));
    return result;
}

bool NapiWebviewController::JsAccessForwardInternal(napi_env env, napi_callback_info info)
{
    bool access = true;
    OHOS::NWeb::NWeb* nweb = OHOS::NWeb::NWebHelper::Instance().GetNWeb(nwebId);

    if (nweb != nullptr) {
        access = nweb->IsNavigateForwardAllowed();
    }

    return access;
}

napi_value NapiWebviewController::JsAccessBackward(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);

    NapiWebviewController *webviewController = nullptr;
    napi_status status = napi_unwrap(env, thisVar, (void **)&webviewController);
    

    if ((!webviewController) || (status != napi_ok)) {
        return nullptr;
    }

    bool access = webviewController->JsAccessForwardInternal(env, info);
    NAPI_CALL(env, napi_get_boolean(env, access, &result));
    return result;
}

bool NapiWebviewController::JsAccessBackwardInternal(napi_env env, napi_callback_info info)
{
    bool access = true;
    OHOS::NWeb::NWeb* nweb = OHOS::NWeb::NWebHelper::Instance().GetNWeb(nwebId);

    if (nweb != nullptr) {
        access = nweb->IsNavigatebackwardAllowed();
    }

    return access;
}

napi_value NapiWebviewController::JsForward(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_value result = nullptr;

    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiWebviewController *webviewController = nullptr;
    napi_unwrap(env, thisVar, (void **)&webviewController);

    if (!webviewController) {
        return result;
    }
    webviewController->JsForwardInternal(env, info);
    NAPI_CALL(env, napi_get_undefined(env, &result));

    return result;
}

void NapiWebviewController::JsForwardInternal(napi_env env, napi_callback_info info)
{
    OHOS::NWeb::NWeb* nweb = OHOS::NWeb::NWebHelper::Instance().GetNWeb(nwebId);

    if (nweb != nullptr) {
        nweb->NavigateForward();
    }
}

napi_value NapiWebviewController::JsBackward(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_value result = nullptr;

    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiWebviewController *webviewController = nullptr;
    napi_unwrap(env, thisVar, (void **)&webviewController);

    if (!webviewController) {
        return result;
    }
    webviewController->JsBackwardInternal(env, info);
    NAPI_CALL(env, napi_get_undefined(env, &result));
    
    return result;
}

void NapiWebviewController::JsBackwardInternal(napi_env env, napi_callback_info info)
{
    OHOS::NWeb::NWeb* nweb = OHOS::NWeb::NWebHelper::Instance().GetNWeb(nwebId);

    if (nweb != nullptr) {
        nweb->NavigateBack();
    }
}
} // namespace OHOS
