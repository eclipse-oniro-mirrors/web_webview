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

#ifndef NWEB_WEB_DEVICE_PERMISSION_DELEGATE_H
#define NWEB_WEB_DEVICE_PERMISSION_DELEGATE_H

#include <functional>
#include <memory>
#include <mutex>
#include <string>

#include <uv.h>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"

#include "nweb_device_permission_delegate.h"
#include "web_device_permission_request.h"

namespace OHOS {
namespace NWeb {

class WebDevicePermissionDelegate;

// Lightweight manager that tracks the active WebDevicePermissionDelegate per
// nwebId. Defined in web_device_permission_delegate.cpp.
namespace WebDevicePermissionManager {
void AddDelegateForWeb(int32_t nwebId, std::shared_ptr<WebDevicePermissionDelegate> delegate);
void RemoveDelegateRef(int32_t nwebId);
} // namespace WebDevicePermissionManager

// WebDevicePermissionDelegate implements the NWebDevicePermissionDelegate
// pure-virtual interface from the glue layer. The arkweb kernel invokes
// OnDevicePicker() when a webpage calls requestDevice(); the application
// resolves the request via the NWebDevicePermissionResultCallback passed to
// OnDevicePicker().
//
// This class is held by shared_ptr: one copy is retained by the JS delegate
// napi wrapper (via NapiWebDevicePermissionDelegate::JS_Constructor's
// napi_wrap deleter) and another is passed to the kernel via
// NWeb::SetDevicePermissionDelegate(). The JS delegate reference (delegate_)
// prevents the JS object from being garbage-collected while the kernel still
// holds a C++ pointer.
//
// Threading model (SEC-THREAD-01 / SEC-THREAD-02 / SEC-UAF-01):
// 1. OnDevicePicker / OnQueryDevicePermission / OnPermissionRevoked /
//    OnDeviceListUpdated may be invoked by the arkweb kernel on a non-JS
//    thread. All NAPI work is marshalled to the JS thread via the env's uv
//    event loop (uv_queue_work, same pattern as WebviewHasImageCallback).
//    The queued work holds a shared_ptr copy so the delegate outlives it.
//    If queueing fails, a pure-C++ fallback resolves the kernel request
//    (OnCancel / OnReply("")) so it is never left dangling.
// 2. ~WebDevicePermissionDelegate performs ZERO NAPI calls, so it is safe to
//    run on any thread (kernel thread included). All napi_refs are released
//    on the JS thread in ReleaseJsReferences(), invoked from the JS wrapper's
//    napi_wrap finalizer — which also runs on the JS thread during env
//    teardown, while the env is still valid (env teardown executes wrap
//    finalizers before destroying the env).
class WebDevicePermissionDelegate : public NWebDevicePermissionDelegate,
                                    public std::enable_shared_from_this<WebDevicePermissionDelegate> {
public:
    explicit WebDevicePermissionDelegate(napi_env env);
    ~WebDevicePermissionDelegate() override;

    // NWebDevicePermissionDelegate override. Called by the arkweb kernel
    // (via the glue layer) when a webpage invokes requestDevice(). The
    // implementation builds a JS WebDevicePermissionRequest object, wraps
    // the request data inside it, and dispatches it to the application's
    // onDevicePicker callback.
    void OnDevicePicker(int32_t nweb_id, const std::string& request_id,
                        const NWebDevicePermissionRequestBase& request_info,
                        const std::vector<NWebDevicePermissionDeviceIdentifier>& devices,
                        std::shared_ptr<NWebDevicePermissionResultCallback> callback) override;

    void OnQueryDevicePermission(int32_t nweb_id,
                                        std::shared_ptr<NWebPermissionOriginsResultCallback> callback) override;

    void OnPermissionRevoked(int32_t nweb_id, const NWebDevicePermissionRevokedEvent& event) override;

    void OnDeviceListUpdated(int32_t nweb_id, const NWebDeviceListUpdateEvent& event) override;

    // Stores the JS callback registered via onDevicePicker(callback).
    void PutOnDevicePicker(napi_env env, napi_value callback);
    void PutOnQueryDevicePermission(napi_env env, napi_value callback);
    void PutOnPermissionRevoked(napi_env env, napi_value callback);
    void PutOnDeviceListUpdated(napi_env env, napi_value callback);

    napi_env GetEnv();

    void RemoveSelfRef();

    // Deletes all napi_refs owned by this delegate (the four callback refs
    // plus the JS delegate self-reference). MUST be called on the JS thread
    // with a live env (the napi_wrap finalizer of the JS delegate object
    // does this, including during env teardown). After this call the
    // destructor performs no NAPI work on any thread.
    void ReleaseJsReferences(napi_env env);

    // Reference to the JS delegate object itself, to prevent it from being
    // garbage-collected while arkweb still holds a pointer to this C++
    // object.
    napi_ref delegate_ = nullptr;

private:
    napi_ref on_device_picker_callback_ = nullptr;
    napi_ref on_query_permission_origins_callback_ = nullptr;
    napi_ref on_permission_revoked_callback_ = nullptr;
    napi_ref on_device_list_updated_callback_ = nullptr;
    napi_env env_ = nullptr;

    // Protects the callback napi_ref members below. The kernel thread reads
    // on_device_picker_callback_ in OnDevicePicker's early null-check
    // (SEC-THREAD-02), while the JS thread writes/deletes the refs via
    // ReplaceCallbackRef and ReleaseJsReferences. All other ref accesses
    // happen on the JS thread (posted lambdas), serialized against the
    // writers by the JS thread itself.
    std::mutex refs_mutex_;

    // Helper to safely replace a napi_ref.
    void ReplaceCallbackRef(napi_env env, napi_value callback, napi_ref &ref);

    // Kernel callback arguments of one device picker request, grouped so the
    // builder helpers below keep a small parameter list.
    struct PickerRequestArgs {
        int32_t nwebId = -1;
        std::string requestId;
        NWebDevicePermissionRequestBase requestInfo;
        std::vector<NWebDevicePermissionDeviceIdentifier> devices;
        std::shared_ptr<NWebDevicePermissionResultCallback> callback;
    };

    // Builds the JS WebDevicePermissionRequest object, wraps the C++ struct,
    // and dispatches it to the onDevicePicker callback. Cancels the kernel
    // request if the object cannot be built. Must run on the JS thread.
    void BuildAndDispatchRequest(napi_env env, napi_value callbackFunc,
                                 const PickerRequestArgs &args);

    // JS-thread continuation of OnDevicePicker: re-checks the delegate state
    // (the finalizer may have released refs while the work was queued),
    // resolves the onDevicePicker callback ref and dispatches the request.
    // Every failure path resolves args.callback with OnCancel().
    void DispatchPickerRequest(const PickerRequestArgs &args);

    // Allocates and fills the C++ WebDevicePermissionRequest from the kernel
    // callback arguments. Caller owns the raw pointer until it is wrapped.
    static WebDevicePermissionRequest *BuildRequest(const PickerRequestArgs &args);

    // Creates the JS request object and napi_wraps |request| (ownership
    // transfers to the finalizer on success). Returns nullptr on failure.
    static napi_value WrapRequestObject(napi_env env, WebDevicePermissionRequest *request);

    // Dispatches a JS callback with a single argument on the current (JS)
    // thread. If the callback ref is null or the call fails, invokes
    // |fallback| (if non-null) so the kernel request is not left dangling.
    void DispatchCallback(napi_env env, napi_ref ref, napi_value arg,
                          const std::function<void()> &fallback = nullptr);

    // Queues |handler| to run on the env's uv loop (JS thread). |self| keeps
    // the delegate alive until the work has run. Falls back to |fallback|
    // (pure C++, may run inline on the caller thread) when queueing fails so
    // kernel requests are never left dangling.
    void PostToJsThread(const std::function<void()> &handler, const std::function<void()> &fallback);

    // ---- uv work marshalling (same pattern as WebviewHasImageCallback) ----
    struct UvWorkData {
        std::function<void()> handler;
    };
    static void UvAfterWorkCb(uv_work_t *work, int status);
};
} // namespace NWeb
} // namespace OHOS

#endif // NWEB_WEB_DEVICE_PERMISSION_DELEGATE_H
