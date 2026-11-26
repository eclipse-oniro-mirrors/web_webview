/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "napi_web_device_permission_request.h"

#include "napi_web_device_permission_helpers.h"

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "nweb_log.h"
#include "web_device_permission_request.h"

namespace OHOS {
namespace NWeb {

namespace {

// Builds a JS WebDeviceIdentifier object from a C++ struct.
napi_value CreateDeviceIdentifier(napi_env env, const WebDeviceIdentifier &dev)
{
    napi_value obj = nullptr;
    napi_status status = napi_create_object(env, &obj);
    if (status != napi_ok || obj == nullptr) {
        WVLOG_E("CreateDeviceIdentifier create object failed, ret=%{public}d",
                static_cast<int32_t>(status));
        return nullptr;
    }
    napi_set_named_property(env, obj, "vendorId", NapiDevicePerm_CreateInt32(env, dev.vendorId));
    napi_set_named_property(env, obj, "productId", NapiDevicePerm_CreateInt32(env, dev.productId));
    napi_set_named_property(env, obj, "deviceKey", NapiDevicePerm_CreateString(env, dev.deviceKey));
    napi_set_named_property(env, obj, "deviceName", NapiDevicePerm_CreateString(env, dev.deviceName));
    return obj;
}

// Builds a JS WebPermissionRequestBase object from a C++ struct.
napi_value CreateRequestInfo(napi_env env, const WebPermissionRequestBase &info)
{
    napi_value obj = nullptr;
    napi_status status = napi_create_object(env, &obj);
    if (status != napi_ok || obj == nullptr) {
        WVLOG_E("CreateRequestInfo create object failed, ret=%{public}d",
                static_cast<int32_t>(status));
        return nullptr;
    }
    napi_set_named_property(env, obj, "hardwareType",
        NapiDevicePerm_CreateInt32(env, static_cast<int32_t>(info.hardwareType)));
    napi_set_named_property(env, obj, "origin", NapiDevicePerm_CreateString(env, info.origin));
    napi_set_named_property(env, obj, "incognito", NapiDevicePerm_CreateBool(env, info.isIncognito));
    return obj;
}

// Forwards the user's selection to the arkweb kernel; the kernel-side
// handler resolves the underlying CEF chooser callback.
void NotifyKernelSelect(WebDevicePermissionRequest *request, const WebDeviceIdentifier &device)
{
    if (request == nullptr) {
        WVLOG_E("NotifyKernelSelect request is null");
        return;
    }
    WVLOG_I("NotifyKernelSelect nwebId=%{public}d requestId=%{public}s deviceKey=%{public}s",
            request->nwebId, request->requestId.c_str(), device.deviceKey.c_str());
    if (!request->callback) {
        WVLOG_W("NotifyKernelSelect callback is null, kernel hookup not present");
        return;
    }
    NWebDevicePermissionDeviceIdentifier nwebDevice;
    nwebDevice.vendor_id = device.vendorId;
    nwebDevice.product_id = device.productId;
    nwebDevice.device_key = device.deviceKey;
    nwebDevice.device_name = device.deviceName;
    request->callback->OnSelect(nwebDevice);
}

void NotifyKernelCancel(WebDevicePermissionRequest *request)
{
    if (request == nullptr) {
        WVLOG_E("NotifyKernelCancel request is null");
        return;
    }
    WVLOG_I("NotifyKernelCancel nwebId=%{public}d requestId=%{public}s",
            request->nwebId, request->requestId.c_str());
    if (!request->callback) {
        WVLOG_W("NotifyKernelCancel callback is null, kernel hookup not present");
        return;
    }
    request->callback->OnCancel();
}

} // namespace

// Defines the methods on a napi object that wraps a WebDevicePermissionRequest.
// Used by WebDevicePermissionDelegate::OnDevicePicker to build the request
// object handed to the application's onDevicePicker callback.
void NapiWebDevicePermissionRequest_DefineProperties(napi_env env, napi_value *obj)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("getRequestInfo", NapiWebDevicePermissionRequest::JS_GetRequestInfo),
        DECLARE_NAPI_FUNCTION("getRequestId", NapiWebDevicePermissionRequest::JS_GetRequestId),
        DECLARE_NAPI_FUNCTION("getDeviceList", NapiWebDevicePermissionRequest::JS_GetDeviceList),
        DECLARE_NAPI_FUNCTION("select", NapiWebDevicePermissionRequest::JS_Select),
        DECLARE_NAPI_FUNCTION("cancel", NapiWebDevicePermissionRequest::JS_Cancel),
    };
    napi_status status = napi_define_properties(
        env, *obj, sizeof(properties) / sizeof(properties[0]), properties);
    if (status != napi_ok) {
        WVLOG_E("NapiWebDevicePermissionRequest_DefineProperties failed, ret=%{public}d",
                static_cast<int32_t>(status));
    }
}

napi_value NapiWebDevicePermissionRequest::JS_GetRequestInfo(napi_env env, napi_callback_info cbinfo)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, nullptr, &thisVar, nullptr);

    WebDevicePermissionRequest *request = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&request));
    if (status != napi_ok || request == nullptr) {
        WVLOG_E("JS_GetRequestInfo unwrap failed, ret=%{public}d",
                static_cast<int32_t>(status));
        return nullptr;
    }
    return CreateRequestInfo(env, request->requestInfo);
}

napi_value NapiWebDevicePermissionRequest::JS_GetRequestId(napi_env env, napi_callback_info cbinfo)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, nullptr, &thisVar, nullptr);

    WebDevicePermissionRequest *request = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&request));
    if (status != napi_ok || request == nullptr) {
        WVLOG_E("JS_GetRequestId unwrap failed, ret=%{public}d",
                static_cast<int32_t>(status));
        return nullptr;
    }
    return NapiDevicePerm_CreateString(env, request->requestId);
}

napi_value NapiWebDevicePermissionRequest::JS_GetDeviceList(napi_env env, napi_callback_info cbinfo)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, nullptr, &thisVar, nullptr);

    WebDevicePermissionRequest *request = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&request));
    if (status != napi_ok || request == nullptr) {
        WVLOG_E("JS_GetDeviceList unwrap failed, ret=%{public}d",
                static_cast<int32_t>(status));
        return nullptr;
    }
    napi_value array = nullptr;
    status = napi_create_array_with_length(env, request->deviceList.size(), &array);
    if (status != napi_ok || array == nullptr) {
        WVLOG_E("JS_GetDeviceList create array failed, ret=%{public}d",
                static_cast<int32_t>(status));
        return nullptr;
    }
    for (size_t i = 0; i < request->deviceList.size(); ++i) {
        napi_value item = CreateDeviceIdentifier(env, request->deviceList[i]);
        if (item != nullptr) {
            napi_set_element(env, array, static_cast<uint32_t>(i), item);
        }
    }
    return array;
}

napi_value NapiWebDevicePermissionRequest::JS_Select(napi_env env, napi_callback_info cbinfo)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, nullptr);

    WebDevicePermissionRequest *request = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&request));
    if (status != napi_ok || request == nullptr) {
        WVLOG_E("JS_Select unwrap failed, ret=%{public}d",
                static_cast<int32_t>(status));
        return nullptr;
    }
    if (request->answered) {
        WVLOG_W("JS_Select already answered, requestId=%{public}s",
                request->requestId.c_str());
        return nullptr;
    }
    WebDeviceIdentifier device;
    if (!NapiDevicePerm_ParseDeviceIdentifier(env, argv[0], device)) {
        WVLOG_E("JS_Select parse device failed, requestId=%{public}s",
                request->requestId.c_str());
        return nullptr;
    }
    // The selected device must come from getDeviceList(); a device outside
    // the list is treated as cancel (interface definition, state machine).
    bool inList = false;
    for (const auto &candidate : request->deviceList) {
        if (candidate.deviceKey == device.deviceKey) {
            inList = true;
            device = candidate;
            break;
        }
    }
    request->answered = true;
    if (!inList) {
        WVLOG_W("JS_Select device not in device list, treating as cancel, "
                "requestId=%{public}s deviceKey=%{public}s",
                request->requestId.c_str(), device.deviceKey.c_str());
        NotifyKernelCancel(request);
        return nullptr;
    }
    NotifyKernelSelect(request, device);
    return nullptr;
}

napi_value NapiWebDevicePermissionRequest::JS_Cancel(napi_env env, napi_callback_info cbinfo)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, nullptr, &thisVar, nullptr);

    WebDevicePermissionRequest *request = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&request));
    if (status != napi_ok || request == nullptr) {
        WVLOG_E("JS_Cancel unwrap failed, ret=%{public}d",
                static_cast<int32_t>(status));
        return nullptr;
    }
    if (request->answered) {
        WVLOG_W("JS_Cancel already answered, requestId=%{public}s",
                request->requestId.c_str());
        return nullptr;
    }
    request->answered = true;
    NotifyKernelCancel(request);
    return nullptr;
}

napi_value NapiWebDevicePermissionRequest::JS_Constructor(napi_env env, napi_callback_info cbinfo)
{
    // Not constructed by applications; the constructor exists only so the
    // class can be registered on exports.
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

napi_value NapiWebDevicePermissionRequest::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("getRequestInfo", JS_GetRequestInfo),
        DECLARE_NAPI_FUNCTION("getRequestId", JS_GetRequestId),
        DECLARE_NAPI_FUNCTION("getDeviceList", JS_GetDeviceList),
        DECLARE_NAPI_FUNCTION("select", JS_Select),
        DECLARE_NAPI_FUNCTION("cancel", JS_Cancel),
    };
    const std::string WEB_DEVICE_PERMISSION_REQUEST = "WebPermissionRequest";
    napi_value klass = nullptr;
    napi_status status = napi_define_class(env, WEB_DEVICE_PERMISSION_REQUEST.c_str(),
        WEB_DEVICE_PERMISSION_REQUEST.length(), JS_Constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &klass);
    if (status != napi_ok) {
        WVLOG_E("NapiWebDevicePermissionRequest::Init define class failed, ret=%{public}d",
                static_cast<int32_t>(status));
        return exports;
    }
    status = napi_set_named_property(env, exports, WEB_DEVICE_PERMISSION_REQUEST.c_str(), klass);
    if (status != napi_ok) {
        WVLOG_E("NapiWebDevicePermissionRequest::Init set named property failed, ret=%{public}d",
                static_cast<int32_t>(status));
    }
    return exports;
}
} // namespace NWeb
} // namespace OHOS
