/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "webview_javascript_execute_callback.h"

#include "business_error.h"
#include "napi_parse_utils.h"
#include "nweb_log.h"
#include "web_errors.h"

namespace {
constexpr int32_t PARAMZERO = 0;
constexpr int32_t PARAMONE = 1;
constexpr int32_t RESULT_COUNT = 2;
}

namespace OHOS::NWeb {
using namespace NWebError;

void WebviewJavaScriptExecuteCallback::OnReceiveValue(std::string result)
{
    WVLOG_D("WebviewJavaScriptExecuteCallback::OnReceiveValue, result = %{public}s", result.c_str());
    uv_loop_s *loop = nullptr;
    uv_work_t *work = nullptr;

    napi_get_uv_event_loop(env_, &loop);
    if (loop == nullptr) {
        return;
    }
    work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        return;
    }

    JavaScriptExecuteParam *param = new (std::nothrow) JavaScriptExecuteParam();
    if (param == nullptr) {
        delete work;
        return;
    }
    param->env_ = env_;
    param->callbackRef_ = callbackRef_;
    param->deferred_ = deferred_;
    param->result_ = result;

    work->data = reinterpret_cast<void*>(param);

    int ret = uv_queue_work(loop, work, [](uv_work_t *work) {}, UvAfterWorkCb);
    if (ret != 0) {
        if (param != nullptr) {
            delete param;
            param = nullptr;
        }
        if (work != nullptr) {
            delete work;
            work = nullptr;
        }
    }
}

void WebviewJavaScriptExecuteCallback::UvAfterWorkCb(uv_work_t* work, int status)
{
    WVLOG_D("WebviewJavaScriptExecuteCallback::UvAfterWorkCb");
    (void)status;
    if (!work) {
        return;
    }
    JavaScriptExecuteParam *param = reinterpret_cast<JavaScriptExecuteParam*>(work->data);
    if (!param) {
        delete work;
        work = nullptr;
        return;
    }

    if (param->callbackRef_) {
        UvAfterWorkCbAsync(param->env_, param->callbackRef_, param->result_);
    } else if (param->deferred_) {
        UvAfterWorkCbPromise(param->env_, param->deferred_, param->result_);
    }

    delete param;
    param = nullptr;
    delete work;
    work = nullptr;
}

void WebviewJavaScriptExecuteCallback::UvAfterWorkCbAsync(napi_env env, napi_ref callbackRef,
    const std::string& result)
{
    WVLOG_D("WebviewJavaScriptExecuteCallback::UvAfterWorkCbAsync");
    napi_value setResult[RESULT_COUNT] = {0};
    if (result.empty()) {
        setResult[PARAMZERO] = BusinessError::CreateError(env, NWebError::INVALID_RESOURCE);
        napi_get_null(env, &setResult[PARAMONE]);
    } else {
        napi_get_undefined(env, &setResult[PARAMZERO]);
        napi_create_string_utf8(env, result.c_str(), NAPI_AUTO_LENGTH, &setResult[PARAMONE]);
    }
    
    napi_value args[RESULT_COUNT] = {setResult[PARAMZERO], setResult[PARAMONE]};
    napi_value callback = nullptr;
    napi_value callbackResult = nullptr;

    napi_get_reference_value(env, callbackRef, &callback);
    napi_call_function(env, nullptr, callback, RESULT_COUNT, args, &callbackResult);
}

void WebviewJavaScriptExecuteCallback::UvAfterWorkCbPromise(napi_env env, napi_deferred deferred,
    const std::string& result)
{
    WVLOG_D("WebviewJavaScriptExecuteCallback::UvAfterWorkCbPromise");
    napi_value setResult[RESULT_COUNT] = {0};
    setResult[PARAMZERO] = NWebError::BusinessError::CreateError(env, NWebError::INVALID_RESOURCE);
    napi_create_string_utf8(env, result.c_str(), NAPI_AUTO_LENGTH, &setResult[PARAMONE]);

    napi_value args[RESULT_COUNT] = {setResult[PARAMZERO], setResult[PARAMONE]};
    if (!result.empty()) {
        napi_resolve_deferred(env, deferred, args[PARAMONE]);
    } else {
        napi_reject_deferred(env, deferred, args[PARAMZERO]);
    }
}

} // namespace NWeb