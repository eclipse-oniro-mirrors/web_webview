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

#include "business_error.h"
#include "nweb.h"
#include "nweb_helper.h"
#include "nweb_log.h"
#include "web_errors.h"

namespace {
constexpr int32_t PARAMZERO = 0;
constexpr int32_t PARAMONE = 1;
constexpr int32_t PARAMTWO = 2;
constexpr int32_t PARAMTHREE = 3;
}

namespace OHOS {
napi_value NapiWebviewController::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("setWebId", NapiWebviewController::JsSetWebId),
        DECLARE_NAPI_FUNCTION("accessForward", NapiWebviewController::JsAccessForward),
        DECLARE_NAPI_FUNCTION("accessBackward", NapiWebviewController::JsAccessBackward),
        DECLARE_NAPI_FUNCTION("accessStep", NapiWebviewController::JsAccessStep),
        DECLARE_NAPI_FUNCTION("clearHistory", NapiWebviewController::JsClearHistory),
        DECLARE_NAPI_FUNCTION("forward", NapiWebviewController::JsForward),
        DECLARE_NAPI_FUNCTION("backward", NapiWebviewController::JsBackward),
        DECLARE_NAPI_FUNCTION("onActive", NapiWebviewController::JsOnActive),
        DECLARE_NAPI_FUNCTION("onInactive", NapiWebviewController::JsOnInactive),
        DECLARE_NAPI_FUNCTION("refresh", NapiWebviewController::JsRefresh),
        DECLARE_NAPI_FUNCTION("zoomIn", NapiWebviewController::JsZoomIn),
        DECLARE_NAPI_FUNCTION("zoomOut", NapiWebviewController::JsZoomOut),
        DECLARE_NAPI_FUNCTION("getWebId", NapiWebviewController::JsGetWebId),
        DECLARE_NAPI_FUNCTION("getDefaultUserAgent", NapiWebviewController::JsGetDefaultUserAgent),
        DECLARE_NAPI_FUNCTION("getTitle", NapiWebviewController::JsGetTitle),
        DECLARE_NAPI_FUNCTION("getPageHeight", NapiWebviewController::JsGetPageHeight),
        DECLARE_NAPI_FUNCTION("backOrForward", NapiWebviewController::JsBackOrForward),
        DECLARE_NAPI_FUNCTION("storeWebArchive", NapiWebviewController::JsStoreWebArchive),
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
    size_t argc = 1;
    napi_value argv[1] = { 0 };
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
    WebviewController *webviewController = new WebviewController(webId);
    napi_status status = napi_wrap(
        env, thisVar, webviewController,
        [](napi_env env, void *data, void *hint) {
            WebviewController *webviewController = static_cast<WebviewController *>(data);
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

bool NapiWebviewController::GetBooleanPara(napi_env env, napi_value argv, bool& outValue)
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

napi_value NapiWebviewController::JsAccessForward(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    
    WebviewController *webviewController = nullptr;
    napi_status status = napi_unwrap(env, thisVar, (void **)&webviewController);
    if ((!webviewController) || (status != napi_ok)) {
        return nullptr;
    }

    bool access = webviewController->AccessForward();
    NAPI_CALL(env, napi_get_boolean(env, access, &result));
    return result;
}

napi_value NapiWebviewController::JsAccessBackward(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);

    WebviewController *webviewController = nullptr;
    napi_status status = napi_unwrap(env, thisVar, (void **)&webviewController);
    if ((!webviewController) || (status != napi_ok)) {
        return nullptr;
    }

    bool access = webviewController->AccessBackward();
    NAPI_CALL(env, napi_get_boolean(env, access, &result));
    return result;
}

napi_value NapiWebviewController::JsForward(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);

    WebviewController *webviewController = nullptr;
    napi_status status = napi_unwrap(env, thisVar, (void **)&webviewController);
    if ((!webviewController) || (status != napi_ok)) {
        return nullptr;
    }

    bool access =  webviewController->AccessForward();
    if (!access) {
        NWebError::BusinessError::ThrowError(env, NWebError::INVALID_BACK_OR_FORWARD_OPERATION,
            "No history corresponding to forward or backward.");
        return nullptr;
    }

    webviewController->Forward();
    NAPI_CALL(env, napi_get_undefined(env, &result));
    return result;
}

napi_value NapiWebviewController::JsBackward(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);

    WebviewController *webviewController = nullptr;
    napi_status status = napi_unwrap(env, thisVar, (void **)&webviewController);
    if ((!webviewController) || (status != napi_ok)) {
        return nullptr;
    }

    bool access =  webviewController->AccessBackward();
    if (!access) {
        NWebError::BusinessError::ThrowError(env, NWebError::INVALID_BACK_OR_FORWARD_OPERATION,
            "No history corresponding to forward or backward.");
        return nullptr;
    }

    webviewController->Backward();
    NAPI_CALL(env, napi_get_undefined(env, &result));
    return result;
}

napi_value NapiWebviewController::JsAccessStep(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != PARAMONE) {
        NWebError::BusinessError::ThrowError(env, NWebError::PARAM_CHECK_ERROR, "Requires 1 parameter.");
        return nullptr;
    }

    int32_t step = 0;
    if (!GetIntPara(env, argv[0], step)) {
        NWebError::BusinessError::ThrowError(env, NWebError::PARAM_CHECK_ERROR,
            "Parameter is not integer number type.");
        return nullptr;
    }

    WebviewController *webviewController = nullptr;
    napi_status status = napi_unwrap(env, thisVar, (void **)&webviewController);
    if ((!webviewController) || (status != napi_ok)) {
        return nullptr;
    }

    bool access = webviewController->AccessStep(step);
    NAPI_CALL(env, napi_get_boolean(env, access, &result));
    return result;
}

napi_value NapiWebviewController::JsClearHistory(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);

    WebviewController *webviewController = nullptr;
    napi_status status = napi_unwrap(env, thisVar, (void **)&webviewController);
    if ((!webviewController) || (status != napi_ok)) {
        return nullptr;
    }

    webviewController->ClearHistory();
    NAPI_CALL(env, napi_get_undefined(env, &result));
    return result;
}

napi_value NapiWebviewController::JsOnActive(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);

    WebviewController *webviewController = nullptr;
    napi_status status = napi_unwrap(env, thisVar, (void **)&webviewController);
    if ((!webviewController) || (status != napi_ok)) {
        return nullptr;
    }

    webviewController->OnActive();

    NAPI_CALL(env, napi_get_undefined(env, &result));
    return result;
}

napi_value NapiWebviewController::JsOnInactive(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);

    WebviewController *webviewController = nullptr;
    napi_status status = napi_unwrap(env, thisVar, (void **)&webviewController);
    if ((!webviewController) || (status != napi_ok)) {
        return nullptr;
    }

    webviewController->OnInactive();
    NAPI_CALL(env, napi_get_undefined(env, &result));
    return result;
}

napi_value NapiWebviewController::JsRefresh(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);

    WebviewController *webviewController = nullptr;
    napi_status status = napi_unwrap(env, thisVar, (void **)&webviewController);
    if ((!webviewController) || (status != napi_ok)) {
        return nullptr;
    }

    webviewController->Refresh();
    NAPI_CALL(env, napi_get_undefined(env, &result));
    return result;
}

napi_value NapiWebviewController::JsZoomIn(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);

    WebviewController *webviewController = nullptr;
    napi_status status = napi_unwrap(env, thisVar, (void **)&webviewController);
    if ((!webviewController) || (status != napi_ok)) {
        return nullptr;
    }

    webviewController->ZoomIn();
    NAPI_CALL(env, napi_get_undefined(env, &result));
    return result;
}

napi_value NapiWebviewController::JsZoomOut(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);

    WebviewController *webviewController = nullptr;
    napi_status status = napi_unwrap(env, thisVar, (void **)&webviewController);
    if ((!webviewController) || (status != napi_ok)) {
        return nullptr;
    }

    webviewController->ZoomOut();
    NAPI_CALL(env, napi_get_undefined(env, &result));
    return result;
}

napi_value NapiWebviewController::JsGetWebId(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);

    WebviewController *webviewController = nullptr;
    napi_unwrap(env, thisVar, (void **)&webviewController);

    if (!webviewController) {
        return result;
    }
    int32_t webId = webviewController->GetWebId();
    napi_create_int32(env, webId, &result);

    return result;
}

napi_value NapiWebviewController::JsGetDefaultUserAgent(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);

    WebviewController *webviewController = nullptr;
    napi_unwrap(env, thisVar, (void **)&webviewController);

    if (!webviewController) {
        return result;
    }
    std::string userAgent = "";
    userAgent = webviewController->GetDefaultUserAgent();
    napi_create_string_utf8(env, userAgent.c_str(), userAgent.length(), &result);

    return result;
}

napi_value NapiWebviewController::JsGetTitle(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);

    WebviewController *webviewController = nullptr;
    napi_unwrap(env, thisVar, (void **)&webviewController);

    if (!webviewController) {
        return result;
    }
    std::string title = "";
    title = webviewController->GetTitle();
    napi_create_string_utf8(env, title.c_str(), title.length(), &result);

    return result;
}

napi_value NapiWebviewController::JsGetPageHeight(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);

    WebviewController *webviewController = nullptr;
    napi_unwrap(env, thisVar, (void **)&webviewController);

    if (!webviewController) {
        return result;
    }
    int32_t pageHeight = webviewController->GetPageHeight();
    napi_create_int32(env, pageHeight, &result);

    return result;
}

napi_value NapiWebviewController::JsBackOrForward(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    size_t argc = PARAMONE;
    napi_value argv[PARAMONE] = { 0 };
    void* data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

    if (argc != PARAMONE) {
        return nullptr;
    }

    int32_t step = -1;
    if (!GetIntPara(env, argv[PARAMZERO], step)) {
        return nullptr;
    }

    WebviewController *webviewController = nullptr;
    napi_unwrap(env, thisVar, (void **)&webviewController);

    if (!webviewController) {
        return result;
    }
    webviewController->BackOrForward(step);
    NAPI_CALL(env, napi_get_undefined(env, &result));

    return result;
}

napi_value NapiWebviewController::JsStoreWebArchive(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    size_t argc = PARAMONE;
    size_t argcPromise = PARAMTWO;
    size_t argcCallback = PARAMTHREE;
    napi_value argv[PARAMTHREE] = { 0 };

    napi_get_undefined(env, &result);
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);

    if (argc != argcPromise && argc != argcCallback) {
        NWebError::BusinessError::ThrowError(env, NWebError::PARAM_CHECK_ERROR, "Requires 2 or 3 parameters.");
        return result;
    }
    std::string baseName;
    if (!GetStringPara(env, argv[PARAMZERO], baseName)) {
        NWebError::BusinessError::ThrowError(env, NWebError::PARAM_CHECK_ERROR,
            "The parameter is not of string type or the parameter length is too long.");
        return result;
    }

    if (baseName.empty()) {
        NWebError::BusinessError::ThrowError(env, NWebError::PARAM_CHECK_ERROR,
            "BaseName cannot be empty.");
        return result;
    }

    bool autoName = false;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (!GetBooleanPara(env, argv[PARAMONE], autoName)) {
        NWebError::BusinessError::ThrowError(env, NWebError::PARAM_CHECK_ERROR,
            "Parameter is not of boolean type.");
        return result;
    }

    if (argc == argcCallback) {
        napi_valuetype valueType = napi_null;
        napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
        napi_typeof(env, argv[argcCallback - 1], &valueType);
        if (valueType != napi_function) {
            NWebError::BusinessError::ThrowError(env, NWebError::PARAM_CHECK_ERROR,
                "Parameter is not of function type.");
            return result;
        }
    }
    return StoreWebArchiveInternal(env, info, baseName, autoName);
}

napi_value NapiWebviewController::StoreWebArchiveInternal(napi_env env, napi_callback_info info,
    const std::string &baseName, bool autoName)
{
    napi_value thisVar = nullptr;
    size_t argc = PARAMONE;
    size_t argcPromise = PARAMTWO;
    size_t argcCallback = PARAMTHREE;
    napi_value argv[PARAMTHREE] = {0};

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);

    WebviewController *webviewController = nullptr;
    napi_unwrap(env, thisVar, (void **)&webviewController);

    if (!webviewController) {
        return result;
    }

    if (argc == argcCallback) {
        napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
        napi_ref jsCallback = nullptr;
        napi_create_reference(env, argv[argcCallback - 1], 1, &jsCallback);

        if (jsCallback) {
            webviewController->StoreWebArchiveCallback(baseName, autoName, env, std::move(jsCallback));
        }
        return result;
    } else if (argc == argcPromise) {
        napi_deferred deferred = nullptr;
        napi_value promise = nullptr;
        napi_create_promise(env, &deferred, &promise);
        if (promise && deferred) {
            webviewController->StoreWebArchivePromise(baseName, autoName, env, deferred);
        }
        return promise;
    }
    return result;
}
} // namespace OHOS
