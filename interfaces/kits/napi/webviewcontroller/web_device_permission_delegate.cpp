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

#include "web_device_permission_delegate.h"

#include <mutex>
#include <unordered_map>

#include "napi_web_device_permission_request.h"
#include "napi_web_device_permission_callback.h"
#include "napi_web_device_permission_helpers.h"
#include "nweb.h"
#include "nweb_helper.h"
#include "nweb_log.h"
#include "nweb_napi_scope.h"

namespace OHOS {
namespace NWeb {

namespace {
// Maps nwebId -> delegate. Mirrors the pattern used by WebDownloadManager.
std::unordered_map<int32_t, std::shared_ptr<WebDevicePermissionDelegate>> g_webDevicePermissionDelegateMap;
std::mutex g_webDevicePermissionDelegateMutex;
} // namespace

WebDevicePermissionDelegate::WebDevicePermissionDelegate(napi_env env) : env_(env)
{
}

WebDevicePermissionDelegate::~WebDevicePermissionDelegate()
{
    // Remove this delegate from the global map. NOTE (SEC-THREAD-01): the last
    // shared_ptr may be released on a kernel thread. The destructor performs
    // ZERO NAPI operations — all napi_refs have already been deleted on the
    // JS thread by ReleaseJsReferences() (from the JS wrapper's napi_wrap
    // finalizer), so this is pure C++ cleanup and safe on any thread.
    std::lock_guard<std::mutex> lock(g_webDevicePermissionDelegateMutex);
    auto it = g_webDevicePermissionDelegateMap.begin();
    while (it != g_webDevicePermissionDelegateMap.end()) {
        if (it->second.get() == this) {
            it = g_webDevicePermissionDelegateMap.erase(it);
        } else {
            ++it;
        }
    }
}

void WebDevicePermissionDelegate::ReleaseJsReferences(napi_env env)
{
    // Must run on the JS thread with a live env; the JS wrapper's napi_wrap
    // finalizer guarantees this (finalizers also run on the JS thread during
    // env teardown, before the env dies, so there is no UAF window).
    if (env == nullptr) {
        WVLOG_E("ReleaseJsReferences nil env");
        return;
    }
    napi_ref *members[] = {&on_device_picker_callback_,
                           &on_query_permission_origins_callback_,
                           &on_permission_revoked_callback_, &on_device_list_updated_callback_};
    const char *names[] = {"onDeviceSelect", "onQueryDevicePermission",
                           "onDevicePermissionRevoke", "onDeviceListUpdate"};
    // Hold refsMutex_ while deleting/nulling: a kernel thread may be reading
    // these refs concurrently (OnDevicePicker's early null-check).
    std::lock_guard<std::mutex> lock(refsMutex_);
    for (size_t i = 0; i < sizeof(members) / sizeof(members[0]); ++i) {
        if (*members[i] != nullptr) {
            napi_status status = napi_delete_reference(env, *members[i]);
            if (status != napi_ok) {
                WVLOG_E("ReleaseJsReferences delete %{public}s ref failed, ret=%{public}d",
                        names[i], static_cast<int32_t>(status));
            }
            *members[i] = nullptr;
        }
    }
    if (delegate_ != nullptr) {
        napi_status status = napi_delete_reference(env, delegate_);
        if (status != napi_ok) {
            WVLOG_E("ReleaseJsReferences delete delegate_ ref failed, ret=%{public}d",
                    static_cast<int32_t>(status));
        }
        delegate_ = nullptr;
    }
}

void WebDevicePermissionDelegate::RemoveSelfRef()
{
    if (delegate_) {
        if (env_ == nullptr) {
            // Env is gone (finalizer already released the refs); nothing to do.
            return;
        }
        uint32_t refCount = 0;
        napi_status status = napi_reference_unref(env_, delegate_, &refCount);
        if (status != napi_ok) {
            WVLOG_E("RemoveSelfRef napi_reference_unref failed, ret=%{public}d",
                    static_cast<int32_t>(status));
            return;
        }
        if (refCount == 0) {
            status = napi_delete_reference(env_, delegate_);
            if (status != napi_ok) {
                WVLOG_E("RemoveSelfRef delete reference failed, ret=%{public}d",
                        static_cast<int32_t>(status));
                return;
            }
            delegate_ = nullptr;
            WVLOG_I("RemoveSelfRef refCount reached 0, deleted delegate reference");
        }
    } else {
        WVLOG_D("RemoveSelfRef delegate_ is null, nothing to do");
    }
}

void WebDevicePermissionDelegate::PutOnDevicePicker(napi_env env, napi_value callback)
{
    ReplaceCallbackRef(env, callback, on_device_picker_callback_);
}

void WebDevicePermissionDelegate::PutOnQueryDevicePermission(napi_env env, napi_value callback)
{
    ReplaceCallbackRef(env, callback, on_query_permission_origins_callback_);
}

void WebDevicePermissionDelegate::PutOnPermissionRevoked(napi_env env, napi_value callback)
{
    ReplaceCallbackRef(env, callback, on_permission_revoked_callback_);
}

void WebDevicePermissionDelegate::PutOnDeviceListUpdated(napi_env env, napi_value callback)
{
    ReplaceCallbackRef(env, callback, on_device_list_updated_callback_);
}

void WebDevicePermissionDelegate::UvAfterWorkCb(uv_work_t *work, int status)
{
    (void)status;
    if (work == nullptr) {
        return;
    }
    auto *data = static_cast<UvWorkData *>(work->data);
    delete work;
    if (data == nullptr) {
        return;
    }
    if (data->handler) {
        data->handler();
    }
    delete data;
}

void WebDevicePermissionDelegate::PostToJsThread(const std::function<void()> &handler,
                                                 const std::function<void()> &fallback)
{
    if (env_ == nullptr) {
        WVLOG_E("PostToJsThread nil env");
        if (fallback) { fallback(); }
        return;
    }
    uv_loop_s *loop = nullptr;
    napi_status status = napi_get_uv_event_loop(env_, &loop);
    if (status != napi_ok || loop == nullptr) {
        WVLOG_E("PostToJsThread get uv event loop failed, ret=%{public}d", static_cast<int32_t>(status));
        if (fallback) { fallback(); }
        return;
    }
    auto *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        if (fallback) { fallback(); }
        return;
    }
    // The handler holds a shared_ptr copy of this delegate, so it is safe to
    // touch `this` inside it regardless of when the kernel releases its last
    // reference, and the delegate cannot be destroyed while the work is
    // still pending.
    auto self = shared_from_this();
    auto *data = new (std::nothrow) UvWorkData{[self, handler]() { handler(); }};
    if (data == nullptr) {
        delete work;
        if (fallback) { fallback(); }
        return;
    }
    work->data = data;
    int ret = uv_queue_work(loop, work, [](uv_work_t *) {}, UvAfterWorkCb);
    if (ret != 0) {
        WVLOG_E("PostToJsThread uv_queue_work failed, ret=%{public}d", ret);
        delete data;
        delete work;
        if (fallback) { fallback(); }
    }
}

void WebDevicePermissionDelegate::DispatchCallback(napi_env env, napi_ref ref, napi_value arg,
    const std::function<void()> &fallback)
{
    if (!env) {
        WVLOG_E("DispatchCallback nil env");
        if (fallback) { fallback(); }
        return;
    }
    if (!ref) {
        WVLOG_E("DispatchCallback callback ref is null");
        if (fallback) { fallback(); }
        return;
    }
    napi_value callbackFunc = nullptr;
    napi_status status = napi_get_reference_value(env, ref, &callbackFunc);
    if (status != napi_ok || callbackFunc == nullptr) {
        WVLOG_E("DispatchCallback get reference value failed, ret=%{public}d",
                static_cast<int32_t>(status));
        if (fallback) { fallback(); }
        return;
    }
    napi_value result = nullptr;
    status = napi_call_function(env, nullptr, callbackFunc, arg ? 1 : 0, arg ? &arg : nullptr, &result);
    if (status != napi_ok) {
        WVLOG_E("DispatchCallback call function failed, ret=%{public}d",
                static_cast<int32_t>(status));
    }
}

void WebDevicePermissionDelegate::ReplaceCallbackRef(napi_env env, napi_value callback, napi_ref &ref)
{
    if (!env) {
        WVLOG_E("ReplaceCallbackRef nil env");
        return;
    }
    // Hold refsMutex_ while deleting/replacing: a kernel thread may be
    // reading the ref concurrently (OnDevicePicker's early null-check).
    std::lock_guard<std::mutex> lock(refsMutex_);
    if (ref) {
        napi_status status = napi_delete_reference(env, ref);
        if (status != napi_ok) {
            WVLOG_E("ReplaceCallbackRef delete old reference failed, ret=%{public}d",
                    static_cast<int32_t>(status));
        }
        ref = nullptr;
    }
    if (callback == nullptr) {
        return;
    }
    napi_status status = napi_create_reference(env, callback, 1, &ref);
    if (status != napi_ok) {
        WVLOG_E("ReplaceCallbackRef create reference failed, ret=%{public}d",
                static_cast<int32_t>(status));
    }
}

// Runs on the JS thread (posted by OnDevicePicker): re-checks the delegate
// state, resolves the JS callback and dispatches the request. Every failure
// path resolves args.callback with OnCancel() so the kernel request is never
// left dangling.
void WebDevicePermissionDelegate::DispatchPickerRequest(const PickerRequestArgs &args)
{
    // Re-check state on the JS thread: the finalizer may have released the
    // callback refs while this work was queued.
    if (env_ == nullptr || on_device_picker_callback_ == nullptr) {
        if (args.callback) { args.callback->OnCancel(); }
        return;
    }
    OHOS::NApiScope scope(env_);
    if (!scope.IsVaild()) {
        if (args.callback) { args.callback->OnCancel(); }
        return;
    }
    napi_value callbackFunc = nullptr;
    napi_status status = napi_get_reference_value(env_, on_device_picker_callback_, &callbackFunc);
    if (status != napi_ok || callbackFunc == nullptr) {
        WVLOG_E("OnDevicePicker get reference value failed, ret=%{public}d",
                static_cast<int32_t>(status));
        if (args.callback) { args.callback->OnCancel(); }
        return;
    }
    BuildAndDispatchRequest(env_, callbackFunc, args);
}

void WebDevicePermissionDelegate::OnDevicePicker(int32_t nwebId, const std::string& requestId,
    const NWebDevicePermissionRequestBase& request_info,
    const std::vector<NWebDevicePermissionDeviceIdentifier>& devices,
    std::shared_ptr<NWebDevicePermissionResultCallback> callback)
{
    WVLOG_I("WebDevicePermissionDelegate::OnDevicePicker nwebId=%{public}d requestId=%{public}s "
            "deviceCount=%{public}zu",
            nwebId, requestId.c_str(), devices.size());
    if (env_ == nullptr) {
        WVLOG_E("OnDevicePicker nil env");
        if (callback) { callback->OnCancel(); }
        return;
    }
    // This may run on a kernel thread while the JS thread replaces/releases
    // the callback refs. Snapshot the null-check under refsMutex_ to avoid
    // a data race; the queued JS-thread work re-checks under JS-thread
    // ordering, so a ref released right after this check is still handled
    // safely.
    bool hasPickerCallback = false;
    {
        std::lock_guard<std::mutex> lock(refsMutex_);
        hasPickerCallback = on_device_picker_callback_ != nullptr;
    }
    if (!hasPickerCallback) {
        WVLOG_E("OnDevicePicker on_device_picker_callback_ is null, cancelling request");
        // The application never registered onDevicePicker; resolve with
        // cancel so the kernel request is not left dangling.
        if (callback) { callback->OnCancel(); }
        return;
    }
    // SEC-THREAD-02: the kernel may call this on a non-JS thread; marshal all
    // NAPI work to the JS thread via the env's uv loop.
    PickerRequestArgs args;
    args.nwebId = nwebId;
    args.requestId = requestId;
    args.requestInfo = request_info;
    args.devices = devices;
    args.callback = callback;
    PostToJsThread(
        [this, args]() { DispatchPickerRequest(args); },
        [callback]() {
            // Queueing failed: resolve inline so the request is not dangling.
            // Pure C++, no NAPI calls — safe on the kernel thread.
            if (callback) { callback->OnCancel(); }
        });
}

// static
WebDevicePermissionRequest *WebDevicePermissionDelegate::BuildRequest(
    const PickerRequestArgs &args)
{
    auto *request = new WebDevicePermissionRequest();
    request->nwebId = args.nwebId;
    request->requestId = args.requestId;
    request->requestInfo.hardwareType =
        static_cast<WebHardwareType>(args.requestInfo.hardware_type);
    request->requestInfo.origin = args.requestInfo.origin;
    request->requestInfo.isIncognito = args.requestInfo.is_incognito;
    for (const auto &dev : args.devices) {
        WebDeviceIdentifier info;
        info.vendorId = dev.vendor_id;
        info.productId = dev.product_id;
        info.deviceKey = dev.device_key;
        info.deviceName = dev.device_name;
        request->deviceList.push_back(info);
    }
    request->callback = args.callback;
    return request;
}

// static
napi_value WebDevicePermissionDelegate::WrapRequestObject(
    napi_env env, WebDevicePermissionRequest *request)
{
    napi_value requestObj = nullptr;
    napi_status status = napi_create_object(env, &requestObj);
    if (status != napi_ok) {
        WVLOG_E("WrapRequestObject create object failed, ret=%{public}d",
                static_cast<int32_t>(status));
        return nullptr;
    }
    status = napi_wrap(env, requestObj, request,
        [](napi_env, void *data, void *) {
            if (!data) { return; }
            auto *req = static_cast<WebDevicePermissionRequest *>(data);
            if (!req->answered) {
                WVLOG_W("WebDevicePermissionRequest GC'd without select/cancel, "
                        "requestId=%{public}s, cancelling kernel request",
                        req->requestId.c_str());
                if (req->callback) { req->callback->OnCancel(); }
            }
            delete req;
        },
        nullptr, nullptr);
    if (status != napi_ok) {
        WVLOG_E("WrapRequestObject wrap object failed, ret=%{public}d",
                static_cast<int32_t>(status));
        return nullptr;
    }
    return requestObj;
}

void WebDevicePermissionDelegate::BuildAndDispatchRequest(
    napi_env env, napi_value callbackFunc, const PickerRequestArgs &args)
{
    // Runs on the JS thread (from the queued OnDevicePicker work).
    auto cancelIfPresent = [&args]() {
        if (args.callback) { args.callback->OnCancel(); }
    };
    WebDevicePermissionRequest *request = BuildRequest(args);
    napi_value requestObj = WrapRequestObject(env, request);
    if (requestObj == nullptr) {
        delete request;
        cancelIfPresent();
        return;
    }

    NapiWebDevicePermissionRequest_DefineProperties(env, &requestObj);

    napi_value result = nullptr;
    napi_status status = napi_call_function(env, nullptr, callbackFunc, 1, &requestObj, &result);
    if (status != napi_ok) {
        WVLOG_E("OnDevicePicker call onDevicePicker failed, ret=%{public}d",
                static_cast<int32_t>(status));
    } else {
        WVLOG_I("OnDevicePicker dispatched, requestId=%{public}s, deviceCount=%{public}zu",
                request->requestId.c_str(), request->deviceList.size());
    }
}

void WebDevicePermissionDelegate::OnQueryDevicePermission(
    int32_t nwebId,
    std::shared_ptr<NWebPermissionOriginsResultCallback> callback)
{
    WVLOG_I("OnQueryDevicePermission nwebId=%{public}d", nwebId);
    if (env_ == nullptr) {
        WVLOG_E("OnQueryDevicePermission nil env");
        if (callback) { callback->OnReply(""); }
        return;
    }
    // SEC-THREAD-02: marshal the JS interaction to the JS thread.
    PostToJsThread(
        [this, nwebId, callback]() {
            if (env_ == nullptr || on_query_permission_origins_callback_ == nullptr) {
                // Either the finalizer released the refs while this work was
                // queued, or the application never registered
                // onQueryDevicePermission; reply with an empty config
                // (treated as "no granted permissions") so the query is
                // resolved.
                if (callback) { callback->OnReply(""); }
                return;
            }
            OHOS::NApiScope scope(env_);
            if (!scope.IsVaild()) {
                if (callback) { callback->OnReply(""); }
                return;
            }
            // WebDevicePermissionEvent { reply(config): void; cancel(): void }
            napi_value cbObj = NapiWebPermissionOriginsResultCallback::Create(env_, callback);
            if (cbObj == nullptr) {
                WVLOG_E("OnQueryDevicePermission create callback object failed");
                if (callback) { callback->OnReply(""); }
                return;
            }
            // DispatchCallback opens its own scope.
            DispatchCallback(env_, on_query_permission_origins_callback_, cbObj,
                [callback]() { if (callback) { callback->OnReply(""); } });
        },
        [callback]() {
            if (callback) { callback->OnReply(""); }
        });
}

void WebDevicePermissionDelegate::OnPermissionRevoked(
    int32_t nwebId, const NWebDevicePermissionRevokedEvent& event)
{
    WVLOG_D("OnPermissionRevoked nwebId=%{public}d", nwebId);
    if (env_ == nullptr) {
        WVLOG_E("OnPermissionRevoked nil env");
        return;
    }
    // SEC-THREAD-02: marshal the JS interaction to the JS thread.
    PostToJsThread(
        [this, event]() {
            if (env_ == nullptr || on_permission_revoked_callback_ == nullptr) {
                return;
            }
            OHOS::NApiScope scope(env_);
            if (!scope.IsVaild()) {
                return;
            }
            napi_value arg = NapiWebDevicePermissionCallback_CreateRevokedEvent(env_, event);
            DispatchCallback(env_, on_permission_revoked_callback_, arg);
        },
        nullptr);
}

void WebDevicePermissionDelegate::OnDeviceListUpdated(
    int32_t nwebId, const NWebDeviceListUpdateEvent& event)
{
    WVLOG_I("OnDeviceListUpdated nwebId=%{public}d", nwebId);
    if (env_ == nullptr) {
        WVLOG_E("OnDeviceListUpdated nil env");
        return;
    }
    // SEC-THREAD-02: marshal the JS interaction to the JS thread.
    PostToJsThread(
        [this, event]() {
            if (env_ == nullptr || on_device_list_updated_callback_ == nullptr) {
                return;
            }
            OHOS::NApiScope scope(env_);
            if (!scope.IsVaild()) {
                return;
            }
            napi_value arg = NapiWebDevicePermissionCallback_CreateDeviceListUpdateEvent(env_, event);
            DispatchCallback(env_, on_device_list_updated_callback_, arg);
        },
        nullptr);
}

napi_env WebDevicePermissionDelegate::GetEnv()
{
    return env_;
}

// ---- Manager-style helpers, mirroring WebDownloadManager ----

namespace WebDevicePermissionManager {

void AddDelegateForWeb(int32_t nwebId, std::shared_ptr<WebDevicePermissionDelegate> delegate)
{
    WVLOG_I("AddDelegateForWeb nwebId=%{public}d", nwebId);
    {
        std::lock_guard<std::mutex> lock(g_webDevicePermissionDelegateMutex);
        g_webDevicePermissionDelegateMap.insert_or_assign(nwebId, delegate);
    }

    // Register the delegate with the arkweb kernel via the NWeb glue
    // interface. The kernel takes a shared_ptr copy and invokes
    // OnDevicePicker() when a webpage calls requestDevice().
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId);
    if (!nweb_ptr) {
        WVLOG_E("AddDelegateForWeb GetNWeb failed for nwebId=%{public}d", nwebId);
        return;
    }
    nweb_ptr->SetDevicePermissionDelegate(delegate);
    WVLOG_I("AddDelegateForWeb registered nwebId=%{public}d", nwebId);
}

void RemoveDelegateRef(int32_t nwebId)
{
    std::shared_ptr<WebDevicePermissionDelegate> delegate;
    {
        std::lock_guard<std::mutex> lock(g_webDevicePermissionDelegateMutex);
        auto it = g_webDevicePermissionDelegateMap.find(nwebId);
        if (it != g_webDevicePermissionDelegateMap.end()) {
            delegate = it->second;
            g_webDevicePermissionDelegateMap.erase(it);
        }
    }
    // Unregister the delegate from the arkweb kernel so no further callbacks
    // (e.g. onQueryDevicePermission / onPermissionRevoked) reach the JS side.
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId);
    if (nweb_ptr) {
        nweb_ptr->SetDevicePermissionDelegate(nullptr);
    } else {
        WVLOG_E("RemoveDelegateRef GetNWeb failed for nwebId=%{public}d", nwebId);
    }
    if (delegate) {
        delegate->RemoveSelfRef();
    }
}

} // namespace WebDevicePermissionManager

} // namespace NWeb
} // namespace OHOS
