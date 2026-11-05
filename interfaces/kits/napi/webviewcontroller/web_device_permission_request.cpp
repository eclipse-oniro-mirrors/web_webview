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

#include "web_device_permission_request.h"

#include "business_error.h"
#include "napi_parse_utils.h"
#include "nweb_log.h"
#include "web_device_permission_helpers.h"

namespace OHOS {
namespace NWeb {

using namespace NWebError;

namespace {
constexpr const char* WEB_DEVICE_PERMISSION_REQUEST_CLASS_NAME = "WebDevicePermissionRequest";
napi_ref g_requestConstructor = nullptr;
}

napi_value NapiWebDevicePermissionRequest::JsConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    auto holder = std::make_unique<WebDevicePermissionRequestHolder>();
    napi_status status = napi_wrap(env, thisVar, holder.get(),
        [](napi_env /* env */, void *data, void * /* hint */) {
            if (data) {
                delete static_cast<WebDevicePermissionRequestHolder *>(data);
            }
        },
        nullptr, nullptr);
    if (status != napi_ok) {
        WVLOG_E("WebDevicePermissionRequest JsConstructor wrap failed.");
        return nullptr;
    }
    holder.release();
    return thisVar;
}

napi_value NapiWebDevicePermissionRequest::GetRequestInfo(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    WebDevicePermissionRequestHolder *holder = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&holder));
    if (!holder) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return result;
    }
    napi_value jsInfo = nullptr;
    napi_create_object(env, &jsInfo);
    napi_set_named_property(env, jsInfo, "hardwareType",
        NapiParseUtils::ToInt32Value(env, static_cast<int32_t>(holder->requestInfo_.hardware_type)));
    napi_set_named_property(env, jsInfo, "origin", CreateStringValue(env, holder->requestInfo_.origin));
    napi_set_named_property(env, jsInfo, "isIncognito", CreateBoolValue(env, holder->requestInfo_.is_incognito));
    return jsInfo;
}

napi_value NapiWebDevicePermissionRequest::GetRequestId(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    WebDevicePermissionRequestHolder *holder = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&holder));
    if (!holder) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return result;
    }
    return CreateStringValue(env, holder->requestId_);
}

napi_value NapiWebDevicePermissionRequest::GetDeviceList(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    WebDevicePermissionRequestHolder *holder = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&holder));
    if (!holder) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return result;
    }
    napi_value jsDeviceArray = nullptr;
    napi_create_array_with_length(env, holder->devices_.size(), &jsDeviceArray);
    for (size_t i = 0; i < holder->devices_.size(); i++) {
        napi_set_element(env, jsDeviceArray, static_cast<uint32_t>(i),
            CreateDeviceIdentifierJsObject(env, holder->devices_[i]));
    }
    return jsDeviceArray;
}

napi_value NapiWebDevicePermissionRequest::Select(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    if (argc < 1) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return result;
    }
    WebDevicePermissionRequestHolder *holder = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&holder));
    if (!holder || !holder->callback_) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return result;
    }
    NWebDevicePermissionDeviceIdentifier device;
    if (!ParseDeviceIdentifier(env, argv[0], device)) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return result;
    }
    holder->callback_->OnSelect(device);
    return result;
}

napi_value NapiWebDevicePermissionRequest::Cancel(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    WebDevicePermissionRequestHolder *holder = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&holder));
    if (!holder || !holder->callback_) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return result;
    }
    holder->callback_->OnCancel();
    return result;
}

napi_value NapiWebDevicePermissionRequest::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("getRequestInfo", NapiWebDevicePermissionRequest::GetRequestInfo),
        DECLARE_NAPI_FUNCTION("getRequestId", NapiWebDevicePermissionRequest::GetRequestId),
        DECLARE_NAPI_FUNCTION("getDeviceList", NapiWebDevicePermissionRequest::GetDeviceList),
        DECLARE_NAPI_FUNCTION("select", NapiWebDevicePermissionRequest::Select),
        DECLARE_NAPI_FUNCTION("cancel", NapiWebDevicePermissionRequest::Cancel),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, WEB_DEVICE_PERMISSION_REQUEST_CLASS_NAME,
        strlen(WEB_DEVICE_PERMISSION_REQUEST_CLASS_NAME),
        NapiWebDevicePermissionRequest::JsConstructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    napi_status status = napi_set_named_property(
        env, exports, WEB_DEVICE_PERMISSION_REQUEST_CLASS_NAME, constructor);
    if (status != napi_ok) {
        WVLOG_E("init WebDevicePermissionRequest class failed");
        return exports;
    }
    if (g_requestConstructor) {
        napi_delete_reference(env, g_requestConstructor);
    }
    napi_create_reference(env, constructor, 1, &g_requestConstructor);
    return exports;
}

napi_value NapiWebDevicePermissionRequest::CreateInstance(napi_env env, int32_t nwebId,
    const std::string& requestId, const NWebDevicePermissionRequestBase& requestInfo,
    const std::vector<NWebDevicePermissionDeviceIdentifier>& devices,
    std::shared_ptr<NWebDevicePermissionResultCallback> callback)
{
    if (!env || !g_requestConstructor) {
        return nullptr;
    }
    napi_value constructor = nullptr;
    napi_status status = napi_get_reference_value(env, g_requestConstructor, &constructor);
    if (status != napi_ok || constructor == nullptr) {
        return nullptr;
    }
    napi_value instance = nullptr;
    status = napi_new_instance(env, constructor, 0, nullptr, &instance);
    if (status != napi_ok || instance == nullptr) {
        WVLOG_E("WebDevicePermissionRequest create instance failed.");
        return nullptr;
    }
    WebDevicePermissionRequestHolder *holder = nullptr;
    status = napi_unwrap(env, instance, reinterpret_cast<void **>(&holder));
    if (status != napi_ok || holder == nullptr) {
        return nullptr;
    }
    holder->nwebId_ = nwebId;
    holder->requestId_ = requestId;
    holder->requestInfo_ = requestInfo;
    holder->devices_ = devices;
    holder->callback_ = callback;
    return instance;
}
} // namespace NWeb
} // namespace OHOS
