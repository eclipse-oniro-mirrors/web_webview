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

#include "napi_web_device_permission_delegate.h"

#include <memory>

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "nweb_log.h"
#include "web_device_permission_delegate.h"

namespace OHOS {
namespace NWeb {

namespace {
napi_value ToInt32Value(napi_env env, int32_t number)
{
    napi_value result = nullptr;
    napi_create_int32(env, number, &result);
    return result;
}

napi_value CreateEnumConstructor(napi_env env, napi_callback_info info)
{
    napi_value arg = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &arg, nullptr);
    return arg;
}
} // namespace

// Generic registration helper: unwraps the delegate, validates the callback
// is a function, and stores it via the given Put* method.
static napi_value RegisterDelegateCallback(napi_env env, napi_callback_info cbinfo,
    const char *name, void (WebDevicePermissionDelegate::*putMethod)(napi_env, napi_value))
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, nullptr);

    DelegateHolder *holder = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&holder));
    if (status != napi_ok || holder == nullptr || !holder->delegate) {
        WVLOG_E("%{public}s unwrap delegate failed, ret=%{public}d", name,
                static_cast<int32_t>(status));
        return thisVar;
    }
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);
    if (valueType != napi_function) {
        WVLOG_E("%{public}s callback is not a function, type=%{public}d", name,
                static_cast<int32_t>(valueType));
        return thisVar;
    }
    (holder->delegate.get()->*putMethod)(env, argv[0]);
    return thisVar;
}

napi_value NapiWebDevicePermissionDelegate::JS_OnDevicePicker(napi_env env, napi_callback_info cbinfo)
{
    return RegisterDelegateCallback(env, cbinfo, "onDeviceSelect",
        &WebDevicePermissionDelegate::PutOnDevicePicker);
}

napi_value NapiWebDevicePermissionDelegate::JS_OnQueryDevicePermission(napi_env env, napi_callback_info cbinfo)
{
    return RegisterDelegateCallback(env, cbinfo, "onQueryDevicePermission",
        &WebDevicePermissionDelegate::PutOnQueryDevicePermission);
}

napi_value NapiWebDevicePermissionDelegate::JS_OnPermissionRevoked(napi_env env, napi_callback_info cbinfo)
{
    return RegisterDelegateCallback(env, cbinfo, "onDevicePermissionRevoke",
        &WebDevicePermissionDelegate::PutOnPermissionRevoked);
}

napi_value NapiWebDevicePermissionDelegate::JS_OnDeviceListUpdated(napi_env env, napi_callback_info cbinfo)
{
    return RegisterDelegateCallback(env, cbinfo, "onDeviceListUpdate",
        &WebDevicePermissionDelegate::PutOnDeviceListUpdated);
}

napi_value NapiWebDevicePermissionDelegate::JS_Constructor(napi_env env, napi_callback_info cbinfo)
{
    auto *holder = new DelegateHolder();
    holder->delegate = std::make_shared<WebDevicePermissionDelegate>(env);
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, nullptr);
    napi_status status = napi_wrap(
        env, thisVar, holder,
        [](napi_env env, void *data, void * /* hint */) {
            if (data) {
                auto *h = static_cast<DelegateHolder *>(data);
                // Release all napi_refs on the JS thread with a still-valid
                // env (napi_wrap finalizers run on the JS thread, including
                // during env teardown), so the destructor performs zero NAPI
                // calls (SEC-THREAD-01 / SEC-UAF-01).
                if (h->delegate) {
                    h->delegate->ReleaseJsReferences(env);
                }
                h->delegate.reset();
                delete h;
            }
        },
        nullptr, nullptr);
    if (status != napi_ok) {
        WVLOG_E("JS_Constructor napi_wrap failed, ret=%{public}d",
                static_cast<int32_t>(status));
        holder->delegate.reset();
        delete holder;
    }
    return thisVar;
}

static void ExportEnum(napi_env env, napi_value exports, const std::string &name,
    napi_property_descriptor *props, size_t propCount)
{
    napi_value enumObj = nullptr;
    napi_define_class(env, name.c_str(), name.length(), CreateEnumConstructor,
        nullptr, propCount, props, &enumObj);
    napi_set_named_property(env, exports, name.c_str(), enumObj);
}

// Exports the WebHardwareType enum.
static void ExportHardwareTypeEnum(napi_env env, napi_value exports)
{
    napi_property_descriptor hwTypeProps[] = {
        DECLARE_NAPI_STATIC_PROPERTY("USB",
            ToInt32Value(env, static_cast<int32_t>(WebHardwareType::USB))),
        DECLARE_NAPI_STATIC_PROPERTY("SERIAL",
            ToInt32Value(env, static_cast<int32_t>(WebHardwareType::SERIAL))),
        DECLARE_NAPI_STATIC_PROPERTY("HID",
            ToInt32Value(env, static_cast<int32_t>(WebHardwareType::HID))),
        DECLARE_NAPI_STATIC_PROPERTY("BLUETOOTH",
            ToInt32Value(env, static_cast<int32_t>(WebHardwareType::BLUETOOTH))),
    };
    ExportEnum(env, exports, "WebHardwareType", hwTypeProps, sizeof(hwTypeProps) / sizeof(hwTypeProps[0]));
}

// Exports the WebDeviceListUpdateAction enum.
static void ExportDeviceListUpdateActionEnum(napi_env env, napi_value exports)
{
    napi_property_descriptor listActionProps[] = {
        DECLARE_NAPI_STATIC_PROPERTY("ADD",
            ToInt32Value(env, static_cast<int32_t>(WebDeviceListUpdateAction::ADD))),
        DECLARE_NAPI_STATIC_PROPERTY("REMOVE",
            ToInt32Value(env, static_cast<int32_t>(WebDeviceListUpdateAction::REMOVE))),
    };
    ExportEnum(env, exports, "WebDeviceListUpdateAction", listActionProps,
               sizeof(listActionProps) / sizeof(listActionProps[0]));
}

// Exports the WebDeviceGuardPolicy enum.
static void ExportGuardPolicyEnum(napi_env env, napi_value exports)
{
    napi_property_descriptor guardPolicyProps[] = {
        DECLARE_NAPI_STATIC_PROPERTY("ASK",
            ToInt32Value(env, static_cast<int32_t>(WebDeviceGuardPolicy::ASK))),
        DECLARE_NAPI_STATIC_PROPERTY("BLOCK",
            ToInt32Value(env, static_cast<int32_t>(WebDeviceGuardPolicy::BLOCK))),
        DECLARE_NAPI_STATIC_PROPERTY("DEFAULT",
            ToInt32Value(env, static_cast<int32_t>(WebDeviceGuardPolicy::DEFAULT))),
    };
    ExportEnum(env, exports, "WebDeviceGuardPolicy", guardPolicyProps,
               sizeof(guardPolicyProps) / sizeof(guardPolicyProps[0]));
}

napi_value NapiWebDevicePermissionDelegate::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("onDeviceSelect", JS_OnDevicePicker),
        DECLARE_NAPI_FUNCTION("onQueryDevicePermission", JS_OnQueryDevicePermission),
        DECLARE_NAPI_FUNCTION("onDevicePermissionRevoke", JS_OnPermissionRevoked),
        DECLARE_NAPI_FUNCTION("onDeviceListUpdate", JS_OnDeviceListUpdated),
    };
    const std::string delegateName = "WebDevicePermissionDelegate";
    napi_value klass = nullptr;
    napi_status status = napi_define_class(env, delegateName.c_str(),
        delegateName.length(), JS_Constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &klass);
    if (status != napi_ok) {
        WVLOG_E("Init define class failed, ret=%{public}d", static_cast<int32_t>(status));
        return exports;
    }
    napi_set_named_property(env, exports, delegateName.c_str(), klass);
    ExportHardwareTypeEnum(env, exports);
    ExportDeviceListUpdateActionEnum(env, exports);
    ExportGuardPolicyEnum(env, exports);
    return exports;
}
} // namespace NWeb
} // namespace OHOS
