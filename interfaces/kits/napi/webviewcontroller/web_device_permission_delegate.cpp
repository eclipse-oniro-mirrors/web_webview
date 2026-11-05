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

#include "web_device_permission_delegate.h"

#include "business_error.h"
#include "napi_parse_utils.h"
#include "nweb_log.h"
#include "web_device_permission_callback.h"
#include "web_device_permission_helpers.h"
#include "web_device_permission_request.h"

namespace OHOS {
namespace NWeb {

using namespace NWebError;

namespace {
constexpr const char* WEB_DEVICE_PERMISSION_DELEGATE_CLASS_NAME = "WebDevicePermissionDelegate";

bool ParseDelegateCallback(napi_env env, napi_callback_info info, napi_value& thisVar,
    WebDevicePermissionDelegate **delegate)
{
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc < 1) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return false;
    }
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);
    if (valueType != napi_function) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return false;
    }
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(delegate));
    if (*delegate == nullptr) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return false;
    }
    return true;
}
} // namespace

WebDevicePermissionDelegate::WebDevicePermissionDelegate(napi_env env) : env_(env)
{
    WVLOG_D("WebDevicePermissionDelegate::WebDevicePermissionDelegate");
}

WebDevicePermissionDelegate::~WebDevicePermissionDelegate()
{
    WVLOG_D("WebDevicePermissionDelegate::~WebDevicePermissionDelegate");
    if (on_query_permission_callback_) {
        napi_delete_reference(env_, on_query_permission_callback_);
    }
    if (on_permission_revoked_callback_) {
        napi_delete_reference(env_, on_permission_revoked_callback_);
    }
    if (on_device_picker_callback_) {
        napi_delete_reference(env_, on_device_picker_callback_);
    }
    if (on_device_list_updated_callback_) {
        napi_delete_reference(env_, on_device_list_updated_callback_);
    }
}

void WebDevicePermissionDelegate::PutOnQueryDevicePermission(napi_env env, napi_value callback)
{
    if (on_query_permission_callback_) {
        napi_delete_reference(env_, on_query_permission_callback_);
    }
    napi_status status = napi_create_reference(env, callback, 1, &on_query_permission_callback_);
    if (status != napi_ok) {
        WVLOG_E("PutOnQueryDevicePermission create reference failed.");
    }
}

void WebDevicePermissionDelegate::PutOnPermissionRevoked(napi_env env, napi_value callback)
{
    if (on_permission_revoked_callback_) {
        napi_delete_reference(env_, on_permission_revoked_callback_);
    }
    napi_status status = napi_create_reference(env, callback, 1, &on_permission_revoked_callback_);
    if (status != napi_ok) {
        WVLOG_E("PutOnPermissionRevoked create reference failed.");
    }
}

void WebDevicePermissionDelegate::PutOnDevicePicker(napi_env env, napi_value callback)
{
    if (on_device_picker_callback_) {
        napi_delete_reference(env_, on_device_picker_callback_);
    }
    napi_status status = napi_create_reference(env, callback, 1, &on_device_picker_callback_);
    if (status != napi_ok) {
        WVLOG_E("PutOnDevicePicker create reference failed.");
    }
}

void WebDevicePermissionDelegate::PutOnDeviceListUpdated(napi_env env, napi_value callback)
{
    if (on_device_list_updated_callback_) {
        napi_delete_reference(env_, on_device_list_updated_callback_);
    }
    napi_status status = napi_create_reference(env, callback, 1, &on_device_list_updated_callback_);
    if (status != napi_ok) {
        WVLOG_E("PutOnDeviceListUpdated create reference failed.");
    }
}

void WebDevicePermissionDelegate::OnQueryDevicePermissionOrigins(int32_t nwebId,
    std::shared_ptr<NWebPermissionOriginsResultCallback> callback)
{
    WVLOG_D("WebDevicePermissionDelegate::OnQueryDevicePermissionOrigins");
    if (!env_ || !on_query_permission_callback_ || !callback) {
        WVLOG_E("OnQueryDevicePermissionOrigins nil env or callback");
        return;
    }
    napi_value jsEvent = CreateDevicePermissionEventJsObject(env_, callback);
    if (jsEvent == nullptr) {
        return;
    }
    CallJsCallback(env_, on_query_permission_callback_, jsEvent);
}

void WebDevicePermissionDelegate::OnPermissionRevoked(int32_t nwebId,
    const NWebDevicePermissionRevokedEvent& event)
{
    WVLOG_D("WebDevicePermissionDelegate::OnPermissionRevoked");
    if (!env_ || !on_permission_revoked_callback_) {
        WVLOG_E("OnPermissionRevoked nil env or callback");
        return;
    }
    napi_value jsEvent = nullptr;
    napi_create_object(env_, &jsEvent);
    napi_set_named_property(env_, jsEvent, "hardwareType",
        NapiParseUtils::ToInt32Value(env_, static_cast<int32_t>(event.hardware_type)));
    napi_set_named_property(env_, jsEvent, "origin", CreateStringValue(env_, event.origin));
    napi_set_named_property(env_, jsEvent, "device", CreateDeviceIdentifierJsObject(env_, event.device));
    napi_set_named_property(env_, jsEvent, "isIncognito", CreateBoolValue(env_, event.is_incognito));
    CallJsCallback(env_, on_permission_revoked_callback_, jsEvent);
}

void WebDevicePermissionDelegate::OnDevicePicker(int32_t nwebId, const std::string& requestId,
    const NWebDevicePermissionRequestBase& requestInfo,
    const std::vector<NWebDevicePermissionDeviceIdentifier>& devices,
    std::shared_ptr<NWebDevicePermissionResultCallback> callback)
{
    WVLOG_D("WebDevicePermissionDelegate::OnDevicePicker");
    if (!env_ || !on_device_picker_callback_) {
        WVLOG_E("OnDevicePicker nil env or callback");
        return;
    }
    napi_value jsRequest = NapiWebDevicePermissionRequest::CreateInstance(
        env_, nwebId, requestId, requestInfo, devices, callback);
    if (jsRequest == nullptr) {
        WVLOG_E("OnDevicePicker create request instance failed.");
        return;
    }
    CallJsCallback(env_, on_device_picker_callback_, jsRequest);
}

void WebDevicePermissionDelegate::OnDeviceListUpdated(int32_t nwebId,
    const NWebDeviceListUpdateEvent& event)
{
    WVLOG_D("WebDevicePermissionDelegate::OnDeviceListUpdated");
    if (!env_ || !on_device_list_updated_callback_) {
        WVLOG_E("OnDeviceListUpdated nil env or callback");
        return;
    }
    napi_value jsEvent = nullptr;
    napi_create_object(env_, &jsEvent);
    napi_set_named_property(env_, jsEvent, "requestId", CreateStringValue(env_, event.request_id));
    napi_set_named_property(env_, jsEvent, "action",
        NapiParseUtils::ToInt32Value(env_, static_cast<int32_t>(event.action)));
    napi_value jsDeviceArray = nullptr;
    napi_create_array_with_length(env_, event.devices.size(), &jsDeviceArray);
    for (size_t i = 0; i < event.devices.size(); i++) {
        napi_set_element(env_, jsDeviceArray, static_cast<uint32_t>(i),
            CreateDeviceIdentifierJsObject(env_, event.devices[i]));
    }
    napi_set_named_property(env_, jsEvent, "devices", jsDeviceArray);
    CallJsCallback(env_, on_device_list_updated_callback_, jsEvent);
}

napi_value NapiWebDevicePermissionDelegate::JsConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    auto holder = std::make_unique<WebDevicePermissionDelegateHolder>();
    holder->delegate_ = std::shared_ptr<WebDevicePermissionDelegate>(
        new WebDevicePermissionDelegate(env));
    napi_status status = napi_wrap(env, thisVar, holder.get(),
        [](napi_env /* env */, void *data, void * /* hint */) {
            if (data) {
                delete static_cast<WebDevicePermissionDelegateHolder *>(data);
            }
        },
        nullptr, nullptr);
    if (status != napi_ok) {
        WVLOG_E("WebDevicePermissionDelegate JsConstructor wrap failed.");
        return nullptr;
    }
    holder.release();
    return thisVar;
}

napi_value NapiWebDevicePermissionDelegate::OnQueryDevicePermission(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    WebDevicePermissionDelegate *delegate = nullptr;
    if (!ParseDelegateCallback(env, info, thisVar, &delegate)) {
        return nullptr;
    }
    napi_value argv[1] = { 0 };
    size_t argc = 1;
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    delegate->PutOnQueryDevicePermission(env, argv[0]);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value NapiWebDevicePermissionDelegate::OnPermissionRevoked(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    WebDevicePermissionDelegate *delegate = nullptr;
    if (!ParseDelegateCallback(env, info, thisVar, &delegate)) {
        return nullptr;
    }
    napi_value argv[1] = { 0 };
    size_t argc = 1;
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    delegate->PutOnPermissionRevoked(env, argv[0]);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value NapiWebDevicePermissionDelegate::OnDevicePicker(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    WebDevicePermissionDelegate *delegate = nullptr;
    if (!ParseDelegateCallback(env, info, thisVar, &delegate)) {
        return nullptr;
    }
    napi_value argv[1] = { 0 };
    size_t argc = 1;
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    delegate->PutOnDevicePicker(env, argv[0]);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value NapiWebDevicePermissionDelegate::OnDeviceListUpdated(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    WebDevicePermissionDelegate *delegate = nullptr;
    if (!ParseDelegateCallback(env, info, thisVar, &delegate)) {
        return nullptr;
    }
    napi_value argv[1] = { 0 };
    size_t argc = 1;
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    delegate->PutOnDeviceListUpdated(env, argv[0]);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value NapiWebDevicePermissionDelegate::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("onQueryDevicePermission",
            NapiWebDevicePermissionDelegate::OnQueryDevicePermission),
        DECLARE_NAPI_FUNCTION("onPermissionRevoked",
            NapiWebDevicePermissionDelegate::OnPermissionRevoked),
        DECLARE_NAPI_FUNCTION("onDevicePicker",
            NapiWebDevicePermissionDelegate::OnDevicePicker),
        DECLARE_NAPI_FUNCTION("onDeviceListUpdated",
            NapiWebDevicePermissionDelegate::OnDeviceListUpdated),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, WEB_DEVICE_PERMISSION_DELEGATE_CLASS_NAME,
        strlen(WEB_DEVICE_PERMISSION_DELEGATE_CLASS_NAME),
        NapiWebDevicePermissionDelegate::JsConstructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    napi_status status = napi_set_named_property(
        env, exports, WEB_DEVICE_PERMISSION_DELEGATE_CLASS_NAME, constructor);
    if (status != napi_ok) {
        WVLOG_E("init WebDevicePermissionDelegate class failed");
    }
    return exports;
}

} // namespace NWeb
} // namespace OHOS
