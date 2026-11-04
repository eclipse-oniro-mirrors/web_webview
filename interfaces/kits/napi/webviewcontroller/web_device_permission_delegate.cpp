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

napi_value CreateDeviceJsObject(napi_env env, std::shared_ptr<NWebDeviceIdentifier> device)
{
    if (!device) {
        return nullptr;
    }
    napi_value jsDevice = nullptr;
    napi_create_object(env, &jsDevice);
    napi_set_named_property(env, jsDevice, "vendorId",
        NapiParseUtils::ToInt32Value(env, device->GetVendorId()));
    napi_set_named_property(env, jsDevice, "productId",
        NapiParseUtils::ToInt32Value(env, device->GetProductId()));
    napi_set_named_property(env, jsDevice, "deviceKey", CreateStringValue(env, device->GetDeviceKey()));
    napi_set_named_property(env, jsDevice, "deviceName", CreateStringValue(env, device->GetDeviceName()));
    return jsDevice;
}
}

WebDevicePermissionDelegate::WebDevicePermissionDelegate(napi_env env) : env_(env)
{
    WVLOG_D("WebDevicePermissionDelegate::WebDevicePermissionDelegate");
}

WebDevicePermissionDelegate::~WebDevicePermissionDelegate()
{
    WVLOG_D("WebDevicePermissionDelegate::~WebDevicePermissionDelegate");
    if (on_query_origins_callback_) {
        napi_delete_reference(env_, on_query_origins_callback_);
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
    if (delegate_) {
        uint32_t refCount = 0;
        napi_reference_unref(env_, delegate_, &refCount);
        if (refCount == 0) {
            napi_delete_reference(env_, delegate_);
        }
        delegate_ = nullptr;
    }
}

void WebDevicePermissionDelegate::PutOnQueryDevicePermissionOrigins(napi_env env, napi_value callback)
{
    if (on_query_origins_callback_) {
        napi_delete_reference(env_, on_query_origins_callback_);
    }
    napi_status status = napi_create_reference(env_, callback, 1, &on_query_origins_callback_);
    if (status != napi_ok) {
        WVLOG_E("PutOnQueryDevicePermissionOrigins create reference failed.");
    }
}

void WebDevicePermissionDelegate::PutOnPermissionRevoked(napi_env env, napi_value callback)
{
    if (on_permission_revoked_callback_) {
        napi_delete_reference(env_, on_permission_revoked_callback_);
    }
    napi_status status = napi_create_reference(env_, callback, 1, &on_permission_revoked_callback_);
    if (status != napi_ok) {
        WVLOG_E("PutOnPermissionRevoked create reference failed.");
    }
}

void WebDevicePermissionDelegate::PutOnDevicePicker(napi_env env, napi_value callback)
{
    if (on_device_picker_callback_) {
        napi_delete_reference(env_, on_device_picker_callback_);
    }
    napi_status status = napi_create_reference(env_, callback, 1, &on_device_picker_callback_);
    if (status != napi_ok) {
        WVLOG_E("PutOnDevicePicker create reference failed.");
    }
}

void WebDevicePermissionDelegate::PutOnDeviceListUpdated(napi_env env, napi_value callback)
{
    if (on_device_list_updated_callback_) {
        napi_delete_reference(env_, on_device_list_updated_callback_);
    }
    napi_status status = napi_create_reference(env_, callback, 1, &on_device_list_updated_callback_);
    if (status != napi_ok) {
        WVLOG_E("PutOnDeviceListUpdated create reference failed.");
    }
}

void WebDevicePermissionDelegate::OnQueryDevicePermissionOrigins(
    std::shared_ptr<NWebDevicePermissionOriginsEvent> event)
{
    WVLOG_D("WebDevicePermissionDelegate::OnQueryDevicePermissionOrigins");
    if (!env_ || !on_query_origins_callback_ || !event) {
        WVLOG_E("OnQueryDevicePermissionOrigins nil env or callback or event");
        return;
    }
    OHOS::NApiScope scope(env_);
    napi_value callbackFunc = nullptr;
    napi_status status = napi_get_reference_value(env_, on_query_origins_callback_, &callbackFunc);
    if (status != napi_ok || callbackFunc == nullptr) {
        WVLOG_E("get onQueryDevicePermissionOrigins func failed.");
        return;
    }
    napi_value jsEvent = nullptr;
    napi_create_object(env_, &jsEvent);
    napi_value replyFunc = nullptr;
    napi_create_function(
        env_, "reply", NAPI_AUTO_LENGTH,
        [](napi_env env, napi_callback_info info) -> napi_value {
            size_t argc = 1;
            napi_value argv[1] = { 0 };
            napi_value thisVar = nullptr;
            napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
            if (argc < 1) {
                napi_value result = nullptr;
                napi_get_undefined(env, &result);
                return result;
            }
            std::string config;
            NapiParseUtils::ParseString(env, argv[0], config);
            napi_value result = nullptr;
            napi_get_undefined(env, &result);
            return result;
        },
        nullptr, &replyFunc);
    napi_set_named_property(env_, jsEvent, "reply", replyFunc);
    napi_value result = nullptr;
    napi_call_function(env_, nullptr, callbackFunc, 1, &jsEvent, &result);
}

void WebDevicePermissionDelegate::OnPermissionRevoked(
    std::shared_ptr<NWebDevicePermissionRevokedEvent> event)
{
    WVLOG_D("WebDevicePermissionDelegate::OnPermissionRevoked");
    if (!env_ || !on_permission_revoked_callback_ || !event) {
        WVLOG_E("OnPermissionRevoked nil env or callback or event");
        return;
    }
    OHOS::NApiScope scope(env_);
    napi_value callbackFunc = nullptr;
    napi_status status = napi_get_reference_value(env_, on_permission_revoked_callback_, &callbackFunc);
    if (status != napi_ok || callbackFunc == nullptr) {
        WVLOG_E("get onPermissionRevoked func failed.");
        return;
    }
    napi_value jsEvent = nullptr;
    napi_create_object(env_, &jsEvent);
    napi_set_named_property(env_, jsEvent, "hardwareType",
        NapiParseUtils::ToInt32Value(env_, static_cast<int32_t>(event->GetHardwareType())));
    napi_set_named_property(env_, jsEvent, "origin", CreateStringValue(env_, event->GetOrigin()));
    napi_set_named_property(env_, jsEvent, "isIncognito", CreateBoolValue(env_, event->GetIsIncognito()));
    auto device = event->GetDevice();
    if (device) {
        napi_set_named_property(env_, jsEvent, "device", CreateDeviceJsObject(env_, device));
    }
    napi_value result = nullptr;
    napi_call_function(env_, nullptr, callbackFunc, 1, &jsEvent, &result);
}

void WebDevicePermissionDelegate::OnDevicePicker(std::shared_ptr<NWebDevicePermissionRequest> request)
{
    WVLOG_D("WebDevicePermissionDelegate::OnDevicePicker");
    if (!env_ || !on_device_picker_callback_ || !request) {
        WVLOG_E("OnDevicePicker nil env or callback or request");
        return;
    }
    OHOS::NApiScope scope(env_);
    napi_value callbackFunc = nullptr;
    napi_status status = napi_get_reference_value(env_, on_device_picker_callback_, &callbackFunc);
    if (status != napi_ok || callbackFunc == nullptr) {
        WVLOG_E("get onDevicePicker func failed.");
        return;
    }
    napi_value jsRequest = nullptr;
    napi_create_object(env_, &jsRequest);
    napi_set_named_property(env_, jsRequest, "getRequestId",
        CreateStringValue(env_, request->GetRequestId()));
    auto deviceList = request->GetDeviceList();
    napi_value jsDeviceArray = nullptr;
    napi_create_array_with_length(env_, deviceList.size(), &jsDeviceArray);
    for (size_t i = 0; i < deviceList.size(); i++) {
        napi_set_element(env_, jsDeviceArray, static_cast<uint32_t>(i),
            CreateDeviceJsObject(env_, deviceList[i]));
    }
    napi_set_named_property(env_, jsRequest, "getDeviceList", jsDeviceArray);
    napi_value result = nullptr;
    napi_call_function(env_, nullptr, callbackFunc, 1, &jsRequest, &result);
}

void WebDevicePermissionDelegate::OnDeviceListUpdated(std::shared_ptr<NWebDeviceListUpdateEvent> event)
{
    WVLOG_D("WebDevicePermissionDelegate::OnDeviceListUpdated");
    if (!env_ || !on_device_list_updated_callback_ || !event) {
        WVLOG_E("OnDeviceListUpdated nil env or callback or event");
        return;
    }
    OHOS::NApiScope scope(env_);
    napi_value callbackFunc = nullptr;
    napi_status status = napi_get_reference_value(env_, on_device_list_updated_callback_, &callbackFunc);
    if (status != napi_ok || callbackFunc == nullptr) {
        WVLOG_E("get onDeviceListUpdated func failed.");
        return;
    }
    napi_value jsEvent = nullptr;
    napi_create_object(env_, &jsEvent);
    napi_set_named_property(env_, jsEvent, "requestId", CreateStringValue(env_, event->GetRequestId()));
    napi_set_named_property(env_, jsEvent, "action",
        NapiParseUtils::ToInt32Value(env_, static_cast<int32_t>(event->GetAction())));
    auto devices = event->GetDevices();
    napi_value jsDeviceArray = nullptr;
    napi_create_array_with_length(env_, devices.size(), &jsDeviceArray);
    for (size_t i = 0; i < devices.size(); i++) {
        napi_set_element(env_, jsDeviceArray, static_cast<uint32_t>(i),
            CreateDeviceJsObject(env_, devices[i]));
    }
    napi_set_named_property(env_, jsEvent, "devices", jsDeviceArray);
    napi_value result = nullptr;
    napi_call_function(env_, nullptr, callbackFunc, 1, &jsEvent, &result);
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

napi_value NapiWebDevicePermissionDelegate::OnQueryDevicePermissionOrigins(
    napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc < 1) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return nullptr;
    }
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);
    if (valueType != napi_function) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return nullptr;
    }
    WebDevicePermissionDelegate *delegate = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&delegate));
    if (!delegate) {
        WVLOG_E("OnQueryDevicePermissionOrigins delegate is null");
        return nullptr;
    }
    delegate->PutOnQueryDevicePermissionOrigins(env, argv[0]);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value NapiWebDevicePermissionDelegate::OnPermissionRevoked(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc < 1) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return nullptr;
    }
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);
    if (valueType != napi_function) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return nullptr;
    }
    WebDevicePermissionDelegate *delegate = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&delegate));
    if (!delegate) {
        WVLOG_E("OnPermissionRevoked delegate is null");
        return nullptr;
    }
    delegate->PutOnPermissionRevoked(env, argv[0]);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value NapiWebDevicePermissionDelegate::OnDevicePicker(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc < 1) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return nullptr;
    }
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);
    if (valueType != napi_function) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return nullptr;
    }
    WebDevicePermissionDelegate *delegate = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&delegate));
    if (!delegate) {
        WVLOG_E("OnDevicePicker delegate is null");
        return nullptr;
    }
    delegate->PutOnDevicePicker(env, argv[0]);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value NapiWebDevicePermissionDelegate::OnDeviceListUpdated(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc < 1) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return nullptr;
    }
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);
    if (valueType != napi_function) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return nullptr;
    }
    WebDevicePermissionDelegate *delegate = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&delegate));
    if (!delegate) {
        WVLOG_E("OnDeviceListUpdated delegate is null");
        return nullptr;
    }
    delegate->PutOnDeviceListUpdated(env, argv[0]);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value NapiWebDevicePermissionDelegate::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("onQueryDevicePermissionOrigins",
            NapiWebDevicePermissionDelegate::OnQueryDevicePermissionOrigins),
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
