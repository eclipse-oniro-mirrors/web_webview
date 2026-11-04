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
#include "nweb_napi_scope.h"

namespace OHOS {
namespace NWeb {

using namespace NWebError;

namespace {
constexpr const char* WEB_DEVICE_PERMISSION_DELEGATE_CLASS_NAME = "WebDevicePermissionDelegate";

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

// JS methods of the WebDevicePermissionEvent object.

napi_value DevicePermissionEventReply(napi_env env, napi_callback_info info)
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
    NapiDevicePermissionEvent *event = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&event));
    if (!event || !event->callback_) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return result;
    }
    std::string config;
    if (!NapiParseUtils::ParseString(env, argv[0], config)) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return result;
    }
    event->callback_->Reply(config);
    return result;
}

// JS methods of the WebDevicePermissionRequest object.

napi_value DevicePermissionRequestGetRequestInfo(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    NapiDevicePermissionRequest *request = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&request));
    if (!request) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return result;
    }
    napi_value jsInfo = nullptr;
    napi_create_object(env, &jsInfo);
    napi_set_named_property(env, jsInfo, "hardwareType",
        NapiParseUtils::ToInt32Value(env, static_cast<int32_t>(request->request_.request_base.hardware_type)));
    napi_set_named_property(env, jsInfo, "origin",
        CreateStringValue(env, request->request_.request_base.origin));
    napi_set_named_property(env, jsInfo, "isIncognito",
        CreateBoolValue(env, request->request_.request_base.is_incognito));
    return jsInfo;
}

napi_value DevicePermissionRequestGetRequestId(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    NapiDevicePermissionRequest *request = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&request));
    if (!request) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return result;
    }
    return CreateStringValue(env, request->request_.request_id);
}

napi_value DevicePermissionRequestGetDeviceList(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    NapiDevicePermissionRequest *request = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&request));
    if (!request) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return result;
    }
    napi_value jsDeviceArray = nullptr;
    napi_create_array_with_length(env, request->request_.device_list.size(), &jsDeviceArray);
    for (size_t i = 0; i < request->request_.device_list.size(); i++) {
        napi_set_element(env, jsDeviceArray, static_cast<uint32_t>(i),
            CreateDeviceIdentifierJsObject(env, request->request_.device_list[i]));
    }
    return jsDeviceArray;
}

napi_value DevicePermissionRequestSelect(napi_env env, napi_callback_info info)
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
    NapiDevicePermissionRequest *request = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&request));
    if (!request || !request->callback_) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return result;
    }
    NWebDevicePermissionDeviceIdentifier device;
    if (!ParseDeviceIdentifier(env, argv[0], device)) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return result;
    }
    request->callback_->Select(device);
    return result;
}

napi_value DevicePermissionRequestCancel(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    NapiDevicePermissionRequest *request = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&request));
    if (!request || !request->callback_) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return result;
    }
    request->callback_->Cancel();
    return result;
}
} // namespace

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

void WebDevicePermissionDelegate::OnQueryDevicePermission(
    std::shared_ptr<NWebDevicePermissionEventCallback> callback)
{
    WVLOG_D("WebDevicePermissionDelegate::OnQueryDevicePermission");
    if (!env_ || !on_query_permission_callback_ || !callback) {
        WVLOG_E("OnQueryDevicePermission nil env or callback");
        return;
    }
    auto event = std::make_unique<NapiDevicePermissionEvent>();
    event->callback_ = callback;
    napi_value jsEvent = nullptr;
    {
        OHOS::NApiScope scope(env_);
        napi_create_object(env_, &jsEvent);
        napi_value replyFunc = nullptr;
        napi_create_function(env_, "reply", NAPI_AUTO_LENGTH, DevicePermissionEventReply,
            nullptr, &replyFunc);
        napi_set_named_property(env_, jsEvent, "reply", replyFunc);
        napi_status status = napi_wrap(env_, jsEvent, event.get(),
            [](napi_env /* env */, void *data, void * /* hint */) {
                if (data) {
                    delete static_cast<NapiDevicePermissionEvent *>(data);
                }
            },
            nullptr, nullptr);
        if (status != napi_ok) {
            WVLOG_E("OnQueryDevicePermission wrap event failed.");
            return;
        }
        event.release();
        CallJsCallback(env_, on_query_permission_callback_, jsEvent);
    }
}

void WebDevicePermissionDelegate::OnPermissionRevoked(const NWebDevicePermissionRevokedEvent& event)
{
    WVLOG_D("WebDevicePermissionDelegate::OnPermissionRevoked");
    if (!env_ || !on_permission_revoked_callback_) {
        WVLOG_E("OnPermissionRevoked nil env or callback");
        return;
    }
    OHOS::NApiScope scope(env_);
    napi_value jsEvent = nullptr;
    napi_create_object(env_, &jsEvent);
    napi_set_named_property(env_, jsEvent, "hardwareType",
        NapiParseUtils::ToInt32Value(env_, static_cast<int32_t>(event.hardware_type)));
    napi_set_named_property(env_, jsEvent, "origin", CreateStringValue(env_, event.origin));
    napi_set_named_property(env_, jsEvent, "device", CreateDeviceIdentifierJsObject(env_, event.device));
    napi_set_named_property(env_, jsEvent, "isIncognito", CreateBoolValue(env_, event.is_incognito));
    CallJsCallback(env_, on_permission_revoked_callback_, jsEvent);
}

void WebDevicePermissionDelegate::OnDevicePicker(const NWebDevicePermissionRequest& request,
    std::shared_ptr<NWebDevicePermissionResultCallback> callback)
{
    WVLOG_D("WebDevicePermissionDelegate::OnDevicePicker");
    if (!env_ || !on_device_picker_callback_) {
        WVLOG_E("OnDevicePicker nil env or callback");
        return;
    }
    auto requestObj = std::make_unique<NapiDevicePermissionRequest>();
    requestObj->request_ = request;
    requestObj->callback_ = callback;
    OHOS::NApiScope scope(env_);
    napi_value jsRequest = nullptr;
    napi_create_object(env_, &jsRequest);
    napi_value func = nullptr;
    napi_create_function(env_, "getRequestInfo", NAPI_AUTO_LENGTH,
        DevicePermissionRequestGetRequestInfo, nullptr, &func);
    napi_set_named_property(env_, jsRequest, "getRequestInfo", func);
    napi_create_function(env_, "getRequestId", NAPI_AUTO_LENGTH,
        DevicePermissionRequestGetRequestId, nullptr, &func);
    napi_set_named_property(env_, jsRequest, "getRequestId", func);
    napi_create_function(env_, "getDeviceList", NAPI_AUTO_LENGTH,
        DevicePermissionRequestGetDeviceList, nullptr, &func);
    napi_set_named_property(env_, jsRequest, "getDeviceList", func);
    napi_create_function(env_, "select", NAPI_AUTO_LENGTH,
        DevicePermissionRequestSelect, nullptr, &func);
    napi_set_named_property(env_, jsRequest, "select", func);
    napi_create_function(env_, "cancel", NAPI_AUTO_LENGTH,
        DevicePermissionRequestCancel, nullptr, &func);
    napi_set_named_property(env_, jsRequest, "cancel", func);
    napi_status status = napi_wrap(env_, jsRequest, requestObj.get(),
        [](napi_env /* env */, void *data, void * /* hint */) {
            if (data) {
                delete static_cast<NapiDevicePermissionRequest *>(data);
            }
        },
        nullptr, nullptr);
    if (status != napi_ok) {
        WVLOG_E("OnDevicePicker wrap request failed.");
        return;
    }
    requestObj.release();
    CallJsCallback(env_, on_device_picker_callback_, jsRequest);
}

void WebDevicePermissionDelegate::OnDeviceListUpdated(const NWebDevicePermissionListUpdateEvent& event)
{
    WVLOG_D("WebDevicePermissionDelegate::OnDeviceListUpdated");
    if (!env_ || !on_device_list_updated_callback_) {
        WVLOG_E("OnDeviceListUpdated nil env or callback");
        return;
    }
    OHOS::NApiScope scope(env_);
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
    auto delegate = std::make_unique<WebDevicePermissionDelegate>(env);
    napi_status status = napi_wrap(env, thisVar, delegate.get(),
        [](napi_env /* env */, void *data, void * /* hint */) {
            if (data) {
                auto *d = static_cast<WebDevicePermissionDelegate *>(data);
                delete d;
            }
        },
        nullptr, nullptr);
    if (status != napi_ok) {
        WVLOG_E("WebDevicePermissionDelegate JsConstructor wrap failed.");
        return nullptr;
    }
    delegate.release();
    return thisVar;
}

namespace {
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
