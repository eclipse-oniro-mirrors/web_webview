/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "napi_web_scheme_handler_request.h"

#include <js_native_api.h>
#include <js_native_api_types.h>
#include <napi/native_api.h>
#include <securec.h>
#include <cstring>

#include "business_error.h"
#include "web_scheme_handler_request.h"
#include "nweb_log.h"
#include "napi_parse_utils.h"
#include "web_errors.h"

using namespace OHOS::NWebError;

namespace OHOS {
namespace NWeb {
napi_value NapiWebSchemeHandlerRequest::Init(napi_env env, napi_value exports)
{
    WVLOG_D("NapiWebSchemeHandlerRequest::Init");
    ExportWebSchemeHandlerRequestClass(env, &exports);
    return exports;
}

void NapiWebSchemeHandlerRequest::ExportWebSchemeHandlerRequestClass(
    napi_env env, napi_value* exportsPointer)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("getHeader", JS_GetHeader),
        DECLARE_NAPI_FUNCTION("getRequestUrl", JS_GetRequestUrl),
        DECLARE_NAPI_FUNCTION("getRequestMethod", JS_GetRequestMethod),
        DECLARE_NAPI_FUNCTION("getReferrer", JS_GetReferrer),
        DECLARE_NAPI_FUNCTION("isRedirect", JS_IsRedirect),
        DECLARE_NAPI_FUNCTION("isMainFrame", JS_IsMainFrame),
        DECLARE_NAPI_FUNCTION("hasGesture", JS_HasGesture),
        DECLARE_NAPI_FUNCTION("getHttpBodyStream", JS_PostDataStream),
    };
    napi_value webSchemeHandlerRequest = nullptr;
    napi_define_class(env, WEB_SCHEME_HANDLER_REQUEST.c_str(), WEB_SCHEME_HANDLER_REQUEST.length(),
        JS_Constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &webSchemeHandlerRequest);
    napi_set_named_property(env, *exportsPointer, WEB_SCHEME_HANDLER_REQUEST.c_str(),
        webSchemeHandlerRequest);
}

napi_status NapiWebSchemeHandlerRequest::DefineProperties(
    napi_env env, napi_value* object)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("getHeader", JS_GetHeader),
        DECLARE_NAPI_FUNCTION("getRequestUrl", JS_GetRequestUrl),
        DECLARE_NAPI_FUNCTION("getRequestMethod", JS_GetRequestMethod),
        DECLARE_NAPI_FUNCTION("getReferrer", JS_GetReferrer),
        DECLARE_NAPI_FUNCTION("isRedirect", JS_IsRedirect),
        DECLARE_NAPI_FUNCTION("isMainFrame", JS_IsMainFrame),
        DECLARE_NAPI_FUNCTION("hasGesture", JS_HasGesture),
        DECLARE_NAPI_FUNCTION("getHttpBodyStream", JS_PostDataStream),
    };
    return napi_define_properties(env, *object, sizeof(properties) / sizeof(properties[0]), properties);
}

napi_value NapiWebSchemeHandlerRequest::JS_Constructor(napi_env env, napi_callback_info cbinfo)
{
    WVLOG_D("NapiWebSchemeHandlerRequest::JS_Constructor is called");
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, &data);

    WebSchemeHandlerRequest *request = new WebSchemeHandlerRequest(env);

    napi_wrap(
        env, thisVar, request,
        [](napi_env /* env */, void *data, void * /* hint */) {
            WebSchemeHandlerRequest *request = (WebSchemeHandlerRequest *)data;
            delete request;
        },
        nullptr, nullptr);

    return thisVar;
}

napi_value NapiWebSchemeHandlerRequest::JS_GetHeader(napi_env env, napi_callback_info cbinfo)
{
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandlerRequest *request = nullptr;
    napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&request);
    if (!request) {
        WVLOG_E("NapiWebSchemeHandlerRequest::JS_GetHeader request is nullptr");
        return nullptr;
    }
    
    WebHeaderList list = request->GetHeader();
    napi_value result = nullptr;
    napi_create_array(env, &result);
    size_t headerSize = list.size();
    for (size_t index = 0; index < headerSize; index++) {
        napi_value webHeaderObj = nullptr;
        napi_value headerKey = nullptr;
        napi_value headerValue = nullptr;
        NAPI_CALL(env, napi_create_object(env, &webHeaderObj));
        napi_create_string_utf8(env, list[index].first.c_str(), NAPI_AUTO_LENGTH, &headerKey);
        napi_create_string_utf8(env, list[index].second.c_str(), NAPI_AUTO_LENGTH, &headerValue);
        napi_set_named_property(env, webHeaderObj, "headerKey", headerKey);
        napi_set_named_property(env, webHeaderObj, "headerValue", headerValue);
        napi_set_element(env, result, index, webHeaderObj);
    }
    return result;
}

napi_value NapiWebSchemeHandlerRequest::JS_GetRequestUrl(napi_env env, napi_callback_info cbinfo)
{
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandlerRequest *request = nullptr;
    napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&request);
    if (!request) {
        WVLOG_E("NapiWebSchemeHandlerRequest::JS_GetRequestUrl request is nullptr");
        return nullptr;
    }
    
    napi_value value;
    char *result = request->GetRequestUrl();
    napi_status status = napi_create_string_utf8(env, result, NAPI_AUTO_LENGTH, &value);
    if (status != napi_ok) {
        WVLOG_E("NapiWebSchemeHandlerRequest::JS_GetRequestUrl response get url failed");
        return nullptr;
    }
    return value;
}

napi_value NapiWebSchemeHandlerRequest::JS_GetRequestMethod(napi_env env, napi_callback_info cbinfo)
{
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandlerRequest *request = nullptr;
    napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&request);
    if (!request) {
        WVLOG_E("NapiWebSchemeHandlerRequest::JS_GetRequestMethod request is nullptr");
        return nullptr;
    }
    
    napi_value value;
    char *result = request->GetMethod();
    napi_status status = napi_create_string_utf8(env, result, NAPI_AUTO_LENGTH, &value);
    if (status != napi_ok) {
        WVLOG_E("NapiWebSchemeHandlerRequest::JS_GetRequestMethod response get url failed");
        return nullptr;
    }
    return value;
}

napi_value NapiWebSchemeHandlerRequest::JS_GetReferrer(napi_env env, napi_callback_info cbinfo)
{
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandlerRequest *request = nullptr;
    napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&request);
    if (!request) {
        WVLOG_E("NapiWebSchemeHandlerRequest::JS_GetReferrer request is nullptr");
        return nullptr;
    }
    
    napi_value value;
    char *result = request->GetReferrer();
    napi_status status = napi_create_string_utf8(env, result, NAPI_AUTO_LENGTH, &value);
    if (status != napi_ok) {
        WVLOG_E("NapiWebSchemeHandlerRequest::JS_GetReferrer response get url failed");
        return nullptr;
    }
    return value;
}

napi_value NapiWebSchemeHandlerRequest::JS_IsRedirect(napi_env env, napi_callback_info cbinfo)
{
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandlerRequest *request = nullptr;
    napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&request);
    if (!request) {
        WVLOG_E("NapiWebSchemeHandlerRequest::JS_IsRedirect request is nullptr");
        return nullptr;
    }
    
    napi_value value;
    bool result = request->IsRedirect();
    NAPI_CALL(env, napi_get_boolean(env, result, &value));
    return value;
}

napi_value NapiWebSchemeHandlerRequest::JS_IsMainFrame(napi_env env, napi_callback_info cbinfo)
{
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandlerRequest *request = nullptr;
    napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&request);
    if (!request) {
        WVLOG_E("NapiWebSchemeHandlerRequest::JS_IsMainFrame request is nullptr");
        return nullptr;
    }
    
    napi_value value;
    bool result = request->IsMainFrame();
    NAPI_CALL(env, napi_get_boolean(env, result, &value));
    return value;
}

napi_value NapiWebSchemeHandlerRequest::JS_HasGesture(napi_env env, napi_callback_info cbinfo)
{
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandlerRequest *request = nullptr;
    napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&request);
    if (!request) {
        WVLOG_E("NapiWebSchemeHandlerRequest::JS_HasGesture request is nullptr");
        return nullptr;
    }
    
    napi_value value;
    bool result = request->HasGesture();
    NAPI_CALL(env, napi_get_boolean(env, result, &value));
    return value;
}

napi_value NapiWebSchemeHandlerRequest::JS_PostDataStream(napi_env env, napi_callback_info cbinfo)
{
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandlerRequest *request = nullptr;
    napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&request);
    if (!request) {
        WVLOG_E("NapiWebSchemeHandlerRequest::JS_PostDataStream request is nullptr");
        return nullptr;
    }

    ArkWeb_PostDataStream* arkWebPostStream = request->GetPostDataStream();
    if (!arkWebPostStream) {
        WVLOG_D("NapiWebSchemeHandlerRequest::JS_PostDataStream stream is nullptr");
        return nullptr;
    }
    napi_value postDataStreamObject;
    WebPostDataStream* stream = new (std::nothrow) WebPostDataStream(env, arkWebPostStream);
    NAPI_CALL(env, napi_create_object(env, &postDataStreamObject));
    napi_wrap(
        env, postDataStreamObject, stream,
        [](napi_env /* env */, void *data, void * /* hint */) {
            WebPostDataStream *stream = (WebPostDataStream *)data;
            delete stream;
        },
        nullptr, nullptr);
    NapiWebPostDataStream::DefineProperties(env, &postDataStreamObject);
    return postDataStreamObject;
}

napi_value NapiWebSchemeHandlerResponse::Init(napi_env env, napi_value exports)
{
    ExportWebSchemeHandlerResponseClass(env, &exports);
    return exports;
}

void NapiWebSchemeHandlerResponse::ExportWebSchemeHandlerResponseClass(
    napi_env env, napi_value* exportsPointer)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("getUrl", JS_GetUrl),
        DECLARE_NAPI_FUNCTION("setUrl", JS_SetUrl),
        DECLARE_NAPI_FUNCTION("getStatus", JS_GetStatus),
        DECLARE_NAPI_FUNCTION("setStatus", JS_SetStatus),
        DECLARE_NAPI_FUNCTION("getStatusText", JS_GetStatusText),
        DECLARE_NAPI_FUNCTION("setStatusText", JS_SetStatusText),
        DECLARE_NAPI_FUNCTION("getMimeType", JS_GetMimeType),
        DECLARE_NAPI_FUNCTION("setMimeType", JS_SetMimeType),
        DECLARE_NAPI_FUNCTION("getEncoding", JS_GetEncoding),
        DECLARE_NAPI_FUNCTION("setEncoding", JS_SetEncoding),
        DECLARE_NAPI_FUNCTION("getHeaderByName", JS_GetHeaderByName),
        DECLARE_NAPI_FUNCTION("setHeaderByName", JS_SetHeaderByName),
        DECLARE_NAPI_FUNCTION("getNetErrorCode", JS_GetNetErrorCode),
        DECLARE_NAPI_FUNCTION("setNetErrorCode", JS_SetNetErrorCode),
    };
    napi_value webSchemeHandlerResponse = nullptr;
    napi_define_class(env, WEB_SCHEME_HANDLER_RESPONSE.c_str(), WEB_SCHEME_HANDLER_RESPONSE.length(),
        JS_Constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &webSchemeHandlerResponse);
    napi_set_named_property(env, *exportsPointer, WEB_SCHEME_HANDLER_RESPONSE.c_str(),
        webSchemeHandlerResponse);
}

napi_value NapiWebSchemeHandlerResponse::JS_Constructor(napi_env env, napi_callback_info cbinfo)
{
    WVLOG_D("NapiWebSchemeHandlerResponse::JS_Constructor is called");
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, &data);

    WebSchemeHandlerResponse *response = new WebSchemeHandlerResponse(env);

    napi_wrap(
        env, thisVar, response,
        [](napi_env /* env */, void *data, void * /* hint */) {
            WebSchemeHandlerResponse *response = (WebSchemeHandlerResponse *)data;
            delete response;
        },
        nullptr, nullptr);

    return thisVar;
}

napi_value NapiWebSchemeHandlerResponse::JS_GetUrl(napi_env env, napi_callback_info cbinfo)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandlerResponse *response = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&response);
    if (!response) {
        WVLOG_E("NapiWebSchemeHandlerResponse::JS_GetUrl response is nullptr");
        return nullptr;
    }
    
    napi_value urlValue;
    char *result = response->GetUrl();
    napi_status status = napi_create_string_utf8(env, result, NAPI_AUTO_LENGTH, &urlValue);
    OH_ArkWeb_ReleaseString(result);
    if (status != napi_ok) {
        WVLOG_E("NapiWebSchemeHandlerResponse::JS_GetUrl response get url failed");
        return nullptr;
    }
    return urlValue;
}

napi_value NapiWebSchemeHandlerResponse::JS_SetUrl(napi_env env, napi_callback_info cbinfo)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    WebSchemeHandlerResponse *response = nullptr;
    napi_unwrap(env, thisVar, (void **)&response);

    if (!response) {
        WVLOG_E("unwrap WebSchemeHandlerResponse failed");
        return nullptr;
    }
    std::string url = "";
    if (!NapiParseUtils::ParseString(env, argv[0], url)) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return nullptr;
    }
    response->SetUrl(url.c_str());
    return nullptr;
}

napi_value NapiWebSchemeHandlerResponse::JS_GetStatus(napi_env env, napi_callback_info cbinfo)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandlerResponse *response = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&response);
    if (!response) {
        WVLOG_E("NapiWebSchemeHandlerResponse::JS_GetStatus response is nullptr");
        return nullptr;
    }

    napi_value status;
    napi_create_int32(env, response->GetStatus(), &status);
    return status;
}

napi_value NapiWebSchemeHandlerResponse::JS_SetStatus(napi_env env, napi_callback_info cbinfo)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    WebSchemeHandlerResponse *response = nullptr;
    napi_unwrap(env, thisVar, (void **)&response);

    if (!response) {
        WVLOG_E("unwrap WebSchemeHandlerResponse failed");
        return nullptr;
    }
    int32_t status = 0;
    if (!NapiParseUtils::ParseInt32(env, argv[0], status)) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        WVLOG_E("NapiWebSchemeHandlerResponse::JS_SetStatus parse failed");
        return nullptr;
    }
    response->SetStatus(status);
    return nullptr;
}

napi_value NapiWebSchemeHandlerResponse::JS_GetStatusText(napi_env env, napi_callback_info cbinfo)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandlerResponse *response = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&response);
    if (!response) {
        WVLOG_E("NapiWebSchemeHandlerResponse::JS_GetStatusText response is nullptr");
        return nullptr;
    }
    
    napi_value statusText;
    char* result = response->GetStatusText();
    napi_status status = napi_create_string_utf8(env, result, NAPI_AUTO_LENGTH, &statusText);
    OH_ArkWeb_ReleaseString(result);
    if (status != napi_ok) {
        WVLOG_E("NapiWebSchemeHandlerResponse::JS_GetStatusText response get failed");
        return nullptr;
    }
    return statusText;
}

napi_value NapiWebSchemeHandlerResponse::JS_SetStatusText(napi_env env, napi_callback_info cbinfo)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    WebSchemeHandlerResponse *response = nullptr;
    napi_unwrap(env, thisVar, (void **)&response);

    if (!response) {
        WVLOG_E("unwrap WebSchemeHandlerResponse failed");
        return nullptr;
    }
    std::string statusText = "";
    if (!NapiParseUtils::ParseString(env, argv[0], statusText)) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return nullptr;
    }
    response->SetStatusText(statusText.c_str());
    return nullptr;
}

napi_value NapiWebSchemeHandlerResponse::JS_GetMimeType(napi_env env, napi_callback_info cbinfo)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandlerResponse *response = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&response);
    if (!response) {
        WVLOG_E("NapiWebSchemeHandlerResponse::JS_GetMimeType response is nullptr");
        return nullptr;
    }
    
    napi_value mimeType;
    char* result = response->GetMimeType();
    napi_status status = napi_create_string_utf8(env, result, NAPI_AUTO_LENGTH, &mimeType);
    OH_ArkWeb_ReleaseString(result);
    if (status != napi_ok) {
        WVLOG_E("NapiWebSchemeHandlerResponse::JS_GetMimeType response get failed");
        return nullptr;
    }
    return mimeType;
}

napi_value NapiWebSchemeHandlerResponse::JS_SetMimeType(napi_env env, napi_callback_info cbinfo)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);
    WebSchemeHandlerResponse *response = nullptr;
    napi_unwrap(env, thisVar, (void **)&response);

    if (!response) {
        WVLOG_E("unwrap WebSchemeHandlerResponse failed");
        return nullptr;
    }
    std::string mimeType = "";
    if (!NapiParseUtils::ParseString(env, argv[0], mimeType)) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return nullptr;
    }
    response->SetMimeType(mimeType.c_str());
    return nullptr;
}

napi_value NapiWebSchemeHandlerResponse::JS_GetEncoding(napi_env env, napi_callback_info cbinfo)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandlerResponse *response = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&response);
    if (!response) {
        WVLOG_E("NapiWebSchemeHandlerResponse::JS_GetEncoding response is nullptr");
        return nullptr;
    }
    
    napi_value encoding;
    char* result = response->GetEncoding();
    napi_status status = napi_create_string_utf8(env, result, NAPI_AUTO_LENGTH, &encoding);
    OH_ArkWeb_ReleaseString(result);
    if (status != napi_ok) {
        WVLOG_E("NapiWebSchemeHandlerResponse::JS_GetEncoding response get failed");
        return nullptr;
    }
    return encoding;
}

napi_value NapiWebSchemeHandlerResponse::JS_SetEncoding(napi_env env, napi_callback_info cbinfo)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    WebSchemeHandlerResponse *response = nullptr;
    napi_unwrap(env, thisVar, (void **)&response);

    if (!response) {
        WVLOG_E("unwrap WebSchemeHandlerResponse failed");
        return nullptr;
    }
    std::string encoding = "";
    if (!NapiParseUtils::ParseString(env, argv[0], encoding)) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return nullptr;
    }
    response->SetEncoding(encoding.c_str());
    return nullptr;
}

napi_value NapiWebSchemeHandlerResponse::JS_GetHeaderByName(napi_env env, napi_callback_info cbinfo)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandlerResponse *response = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&response);
    if (!response) {
        WVLOG_E("NapiWebSchemeHandlerResponse::JS_GetEncoding response is nullptr");
        return nullptr;
    }

    std::string name;
    if (!NapiParseUtils::ParseString(env, argv[0], name)) {
        return nullptr;
    }
    
    napi_value headerValue;
    char* result = response->GetHeaderByName(name.c_str());
    napi_status status = napi_create_string_utf8(env, result, NAPI_AUTO_LENGTH, &headerValue);
    OH_ArkWeb_ReleaseString(result);
    if (status != napi_ok) {
        WVLOG_E("NapiWebSchemeHandlerResponse::JS_GetEncoding response get failed");
        return nullptr;
    }
    return headerValue;
}

napi_value NapiWebSchemeHandlerResponse::JS_SetHeaderByName(napi_env env, napi_callback_info cbinfo)
{
    size_t argc = INTEGER_THREE;
    napi_value argv[INTEGER_THREE] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    WebSchemeHandlerResponse *response = nullptr;
    napi_unwrap(env, thisVar, (void **)&response);

    if (!response) {
        WVLOG_E("unwrap WebSchemeHandlerResponse failed");
        return nullptr;
    }
    std::string name;
    std::string value;
    bool overwrite = false;
    if (argc != INTEGER_THREE ||
        !NapiParseUtils::ParseString(env, argv[INTEGER_ZERO], name) ||
        !NapiParseUtils::ParseString(env, argv[INTEGER_ONE], value) ||
        !NapiParseUtils::ParseBoolean(env, argv[INTEGER_TWO], overwrite)) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        WVLOG_E("NapiWebSchemeHandlerResponse::JS_SetHeaderByName parse failed");
        return nullptr;
    }
    response->SetHeaderByName(name.c_str(), value.c_str(), overwrite);
    return nullptr;
}

napi_value NapiWebSchemeHandlerResponse::JS_GetNetErrorCode(napi_env env, napi_callback_info cbinfo)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandlerResponse *response = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&response);
    if (!response) {
        WVLOG_E("NapiWebSchemeHandlerResponse::JS_GetEncoding response is nullptr");
        return nullptr;
    }
    
    napi_value code;
    int32_t result = response->GetErrorCode();
    NAPI_CALL(env, napi_create_int32(env, result, &code));
    return code;
}

napi_value NapiWebSchemeHandlerResponse::JS_SetNetErrorCode(napi_env env, napi_callback_info cbinfo)
{
    size_t argc = INTEGER_ONE;
    napi_value argv[INTEGER_ONE] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandlerResponse *response = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&response);
    if (!response) {
        WVLOG_E("NapiWebSchemeHandlerResponse::JS_GetEncoding response is nullptr");
        return nullptr;
    }
    int32_t code = 0;
    if (argc != INTEGER_ONE ||
        !NapiParseUtils::ParseInt32(env, argv[0], code)) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return nullptr;
    }
    response->SetErrorCode(code);
    return nullptr;
}

napi_value NapiWebSchemeHandler::Init(napi_env env, napi_value exports)
{
    WVLOG_D("NapiWebSchemeHandler::Init");
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("onRequestStart", JS_RequestStart),
        DECLARE_NAPI_FUNCTION("onRequestStop", JS_RequestStop),
    };
    napi_value webSchemeHandler = nullptr;
    napi_define_class(env, WEB_SCHEME_HANDLER.c_str(), WEB_SCHEME_HANDLER.length(),
        JS_Constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &webSchemeHandler);
    napi_set_named_property(env, exports, WEB_SCHEME_HANDLER.c_str(),
        webSchemeHandler);
    return exports;
}

napi_value NapiWebSchemeHandler::JS_Constructor(napi_env env, napi_callback_info cbinfo)
{
    WVLOG_D("NapiWebSchemeHandler::JS_Constructor is called");
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, &data);

    WebSchemeHandler *handler = new WebSchemeHandler(env);

    napi_wrap(
        env, thisVar, handler,
        [](napi_env /* env */, void *data, void * /* hint */) {
            WebSchemeHandler *handler = (WebSchemeHandler *)data;
            delete handler;
        },
        nullptr, nullptr);

    return thisVar;
}

napi_value NapiWebSchemeHandler::JS_RequestStart(napi_env env, napi_callback_info info)
{
    WVLOG_D("NapiWebSchemeHandler::JS_RequestStart");
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandler *handler = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&handler);
    if (!handler) {
        WVLOG_E("webSchemeHandler is null");
        return thisVar;
    }

    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);

    handler->PutRequestStart(env, argv[0]);
    return thisVar;
}

napi_value NapiWebSchemeHandler::JS_RequestStop(napi_env env, napi_callback_info info)
{
    WVLOG_D("NapiWebSchemeHandler::JS_RequestStop");
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandler *handler = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&handler);
    if (!handler) {
        WVLOG_E("webSchemeHandler is null");
        return thisVar;
    }

    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);

    handler->PutRequestStop(env, argv[0]);
    return thisVar;
}

napi_value NapiWebResourceHandler::Init(napi_env env, napi_value exports)
{
    ExportWebResourceHandlerClass(env, &exports);
    return exports;
}

void NapiWebResourceHandler::ExportWebResourceHandlerClass(
    napi_env env, napi_value* exportsPointer)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("didReceiveResponse", JS_DidReceiveResponse),
        DECLARE_NAPI_FUNCTION("didReceiveResponseBody", JS_DidReceiveResponseBody),
        DECLARE_NAPI_FUNCTION("didFinish", JS_DidFinish),
        DECLARE_NAPI_FUNCTION("didFail", JS_DidFailWithError),
    };
    napi_value webResourceHandler = nullptr;
    napi_define_class(env, WEB_RESOURCE_HANDLER.c_str(), WEB_RESOURCE_HANDLER.length(),
        JS_Constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &webResourceHandler);
    napi_set_named_property(env, *exportsPointer, WEB_RESOURCE_HANDLER.c_str(),
        webResourceHandler);
}

napi_status NapiWebResourceHandler::DefineProperties(
    napi_env env, napi_value* object)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("didReceiveResponse", JS_DidReceiveResponse),
        DECLARE_NAPI_FUNCTION("didReceiveResponseBody", JS_DidReceiveResponseBody),
        DECLARE_NAPI_FUNCTION("didFinish", JS_DidFinish),
        DECLARE_NAPI_FUNCTION("didFail", JS_DidFailWithError),
    };
    return napi_define_properties(env, *object, sizeof(properties) / sizeof(properties[0]), properties);
}

napi_value NapiWebResourceHandler::JS_Constructor(napi_env env, napi_callback_info info)
{
    WVLOG_D("NapiWebResourceHandler::JS_Constructor is called");
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, &data);

    WebResourceHandler *handler = new WebResourceHandler(env);

    napi_wrap(
        env, thisVar, handler,
        [](napi_env /* env */, void *data, void * /* hint */) {
            WebResourceHandler *handler = (WebResourceHandler *)data;
            delete handler;
        },
        nullptr, nullptr);

    return thisVar;
}

napi_value NapiWebResourceHandler::JS_DidReceiveResponse(napi_env env, napi_callback_info info)
{
    WVLOG_D("NapiWebResourceHandler::JS_DidReceiveResponse is called");
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

    WebResourceHandler *resourceHandler = nullptr;
    napi_unwrap(env, thisVar, (void **)&resourceHandler);

    if (!resourceHandler) {
        WVLOG_E("JS_DidReceiveResponse unwrap resource handler failed");
        return nullptr;
    }

    WebSchemeHandlerResponse* response = nullptr;
    napi_value obj = argv[0];
    napi_unwrap(env, obj, (void**)&response);
    if (!response) {
        WVLOG_E("JS_DidReceiveResponse unwrap response failed");
        return nullptr;
    }
    int32_t ret =
        resourceHandler->DidReceiveResponse(response->GetArkWebResponse());
    if (ret != 0) {
        BusinessError::ThrowErrorByErrcode(env, RESOURCE_HANDLER_INVALID);
    }
    return nullptr;
}

napi_value NapiWebResourceHandler::JS_DidReceiveResponseBody(napi_env env, napi_callback_info info)
{
    WVLOG_D("NapiWebResourceHandler::JS_DidReceiveResponseBody is called");
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

    if (argc != 1) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return nullptr;
    }

    WebResourceHandler *resourceHandler = nullptr;
    napi_unwrap(env, thisVar, (void **)&resourceHandler);

    if (!resourceHandler) {
        WVLOG_E("unwrap resource handler failed");
        return nullptr;
    }
    bool isArrayBuffer = false;
    NAPI_CALL(env, napi_is_arraybuffer(env, argv[0], &isArrayBuffer));
    if (!isArrayBuffer) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return nullptr;
    }

    uint8_t *arrBuf = nullptr;
    size_t byteLength = 0;
    napi_get_arraybuffer_info(env, argv[0], (void **)&arrBuf, &byteLength);
    int32_t ret = resourceHandler->DidReceiveResponseBody(
        arrBuf, static_cast<int64_t>(byteLength));
    if (ret != 0) {
        WVLOG_E("JS_DidReceiveResponseBody ret=%{public}d", ret);
        BusinessError::ThrowErrorByErrcode(env, RESOURCE_HANDLER_INVALID);
    }
    return nullptr;
}

napi_value NapiWebResourceHandler::JS_DidFinish(napi_env env, napi_callback_info info)
{
    WVLOG_D("NapiWebResourceHandler::JS_DidFinish is called");
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, &data);

    WebResourceHandler *resourceHandler = nullptr;
    napi_unwrap(env, thisVar, (void **)&resourceHandler);

    if (!resourceHandler) {
        WVLOG_E("unwrap resource handler failed");
        return nullptr;
    }

    int32_t ret = resourceHandler->DidFinish();
    if (ret != 0) {
        BusinessError::ThrowErrorByErrcode(env, RESOURCE_HANDLER_INVALID);
        WVLOG_E("JS_DidFinish ret=%{public}d", ret);
    }
    return nullptr;
}

napi_value NapiWebResourceHandler::JS_DidFailWithError(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

    WebResourceHandler *resourceHandler = nullptr;
    napi_unwrap(env, thisVar, (void **)&resourceHandler);

    if (!resourceHandler) {
        WVLOG_E("unwrap resource handler failed");
        return nullptr;
    }

    int32_t errorCode;
    if (!NapiParseUtils::ParseInt32(env, argv[0], errorCode)) {
        WVLOG_E("JS_DidFailWithError unwrap error code failed");
        return nullptr;
    }
    
    int32_t ret = resourceHandler->DidFailWithError(
        static_cast<ArkWeb_NetError>(errorCode));
    if (ret != 0) {
        BusinessError::ThrowErrorByErrcode(env, RESOURCE_HANDLER_INVALID);
        WVLOG_E("JS_DidFailWithError ret=%{public}d", ret);
    }
    return nullptr;
}

napi_value NapiWebPostDataStream::Init(napi_env env, napi_value exports)
{
    ExportWebPostDataStreamClass(env, &exports);
    return exports;
}

void NapiWebPostDataStream::ExportWebPostDataStreamClass(
    napi_env env, napi_value* exportsPointer)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("initialize", JS_Initialize),
        DECLARE_NAPI_FUNCTION("read", JS_Read),
        DECLARE_NAPI_FUNCTION("getSize", JS_GetSize),
        DECLARE_NAPI_FUNCTION("getPosition", JS_GetPostion),
        DECLARE_NAPI_FUNCTION("isChunked", JS_IsChunked),
        DECLARE_NAPI_FUNCTION("isEof", JS_IsEof),
        DECLARE_NAPI_FUNCTION("isInMemory", JS_IsInMemory),
    };
    napi_value webPostDataStream = nullptr;
    napi_define_class(env, WEB_POST_DATA_STREAM.c_str(), WEB_POST_DATA_STREAM.length(),
        JS_Constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &webPostDataStream);
    napi_set_named_property(env, *exportsPointer, WEB_POST_DATA_STREAM.c_str(),
        webPostDataStream);
}

napi_status NapiWebPostDataStream::DefineProperties(
    napi_env env, napi_value* exportsPointer)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("initialize", JS_Initialize),
        DECLARE_NAPI_FUNCTION("read", JS_Read),
        DECLARE_NAPI_FUNCTION("getSize", JS_GetSize),
        DECLARE_NAPI_FUNCTION("getPosition", JS_GetPostion),
        DECLARE_NAPI_FUNCTION("isChunked", JS_IsChunked),
        DECLARE_NAPI_FUNCTION("isEof", JS_IsEof),
        DECLARE_NAPI_FUNCTION("isInMemory", JS_IsInMemory),
    };
    return napi_define_properties(env, *exportsPointer,
        sizeof(properties) / sizeof(properties[0]), properties);
}

napi_value NapiWebPostDataStream::JS_Constructor(napi_env env, napi_callback_info info)
{
    WVLOG_D("NapiWebPostDataStream::JS_Constructor is called");
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, &data);

    WebPostDataStream *stream = new WebPostDataStream(env);
    napi_wrap(
        env, thisVar, stream,
        [](napi_env /* env */, void *data, void * /* hint */) {
            WebPostDataStream *stream = (WebPostDataStream *)data;
            delete stream;
        },
        nullptr, nullptr);
    return thisVar;
}

napi_value NapiWebPostDataStream::JS_Initialize(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = INTEGER_ONE;
    size_t argcPromise = INTEGER_ZERO;
    size_t argcCallback = INTEGER_ONE;
    napi_value argv[INTEGER_ONE] = {0};
    WebPostDataStream *stream = nullptr;
    
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    napi_unwrap(env, thisVar, (void **)&stream);
    if (!stream) {
        WVLOG_E("NapiWebPostDataStream::JS_Initialize stream is nullptr");
        return nullptr;
    }
    if (argc != argcPromise && argc != argcCallback) {
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
        return nullptr;
    }
    if (argc == argcCallback) {
        napi_valuetype valueType = napi_null;
        napi_typeof(env, argv[argcCallback - 1], &valueType);
        if (valueType != napi_function) {
            NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
            return nullptr;
        }
        napi_ref jsCallback = nullptr;
        napi_create_reference(env, argv[argcCallback - 1], INTEGER_ONE, &jsCallback);

        if (jsCallback) {
            stream->Init(std::move(jsCallback), nullptr);
        }
        return result;
    }

    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_create_promise(env, &deferred, &promise);
    if (promise && deferred) {
        stream->Init(nullptr, std::move(deferred));
        return promise;
    }
    return result;
}

napi_value NapiWebPostDataStream::JS_Read(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    void* data = nullptr;
    size_t argc = INTEGER_TWO;
    size_t argcPromise = INTEGER_ONE;
    size_t argcCallback = INTEGER_TWO;
    napi_value argv[INTEGER_TWO] = {0};
    WebPostDataStream *stream = nullptr;
    
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    napi_unwrap(env, thisVar, (void **)&stream);
    if (!stream) {
        WVLOG_E("NapiWebPostDataStream::JS_Initialize stream is nullptr");
        return nullptr;
    }
    if (argc != argcPromise && argc != argcCallback) {
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
        return nullptr;
    }
    int32_t bufLen = 0;
    if (!NapiParseUtils::ParseInt32(env, argv[0], bufLen) || bufLen <= 0) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        WVLOG_E("NapiWebPostDataStream::JS_Read parse failed");
        return nullptr;
    }
    if (argc == argcCallback) {
        napi_valuetype valueType = napi_null;
        napi_typeof(env, argv[argcCallback - 1], &valueType);
        if (valueType != napi_function) {
            NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
            return nullptr;
        }
        napi_ref jsCallback = nullptr;
        napi_create_reference(env, argv[argcCallback - 1], INTEGER_ONE, &jsCallback);

        if (jsCallback) {
            stream->Read(bufLen, std::move(jsCallback), nullptr);
        }
        return result;
    }

    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_create_promise(env, &deferred, &promise);
    if (promise && deferred) {
        stream->Read(bufLen, nullptr, std::move(deferred));
        return promise;
    }
    return result;
}

napi_value NapiWebPostDataStream::JS_GetSize(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebPostDataStream *stream = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&stream);
    if (!stream) {
        WVLOG_E("NapiWebPostDataStream::JS_GetSize stream is nullptr");
        return nullptr;
    }

    napi_value value;
    int64_t result = static_cast<int64_t>(stream->GetSize());
    napi_create_int64(env, result, &value);
    return value;
}

napi_value NapiWebPostDataStream::JS_GetPostion(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebPostDataStream *stream = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&stream);
    if (!stream) {
        WVLOG_E("NapiWebPostDataStream::JS_GetPostion stream is nullptr");
        return nullptr;
    }

    napi_value value;
    int64_t result = static_cast<int64_t>(stream->GetPostion());
    napi_create_int64(env, result, &value);
    return value;
}

napi_value NapiWebPostDataStream::JS_IsChunked(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebPostDataStream *stream = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&stream);
    if (!stream) {
        WVLOG_E("NapiWebPostDataStream::JS_IsChunked stream is nullptr");
        return nullptr;
    }

    napi_value value;
    bool result = stream->IsChunked();
    NAPI_CALL(env, napi_get_boolean(env, result, &value));
    return value;
}

napi_value NapiWebPostDataStream::JS_IsEof(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebPostDataStream *stream = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&stream);
    if (!stream) {
        WVLOG_E("NapiWebPostDataStream::JS_IsEof stream is nullptr");
        return nullptr;
    }

    napi_value value;
    bool result = stream->IsEof();
    NAPI_CALL(env, napi_get_boolean(env, result, &value));
    return value;
}

napi_value NapiWebPostDataStream::JS_IsInMemory(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebPostDataStream *stream = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&stream);
    if (!stream) {
        WVLOG_E("NapiWebPostDataStream::JS_IsInMemory stream is nullptr");
        return nullptr;
    }

    napi_value value;
    bool result = stream->IsInMemory();
    NAPI_CALL(env, napi_get_boolean(env, result, &value));
    return value;
}
}
}
