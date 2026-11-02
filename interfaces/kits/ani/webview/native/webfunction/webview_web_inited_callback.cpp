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

#include "webview_web_inited_callback.h"

#include <memory>

#include "uv.h"

namespace OHOS::NWeb {
constexpr ani_size REFERENCES_MAX_NUMBER = 16;
namespace {
void UvWebInitedCallbackThreadWoker(WebRunInitedCallbackImpl* obj)
{
    WVLOG_D("enter UvWebInitedCallbackThreadWoker");
    if (!obj || !(obj->param_)) {
        WVLOG_E("callback obj or param is nullptr");
        return;
    }
    // 接管 param_ 所有权，保证所有退出路径均能释放 param_，避免 C++ 对象及其持有的 JS 全局引用泄漏
    std::unique_ptr<WebInitedCallbackParam> paramGuard(obj->param_);
    obj->param_ = nullptr;

    ani_size nr_refs = REFERENCES_MAX_NUMBER;
    ani_env* env = paramGuard->GetEnv();
    if (!env) {
        WVLOG_E("env is nullptr");
        return;
    }
    if (env->CreateLocalScope(nr_refs) != ANI_OK) {
        WVLOG_E("env createLocalScope failed");
        return;
    }
    ani_status status;
    if (paramGuard->webInitedCallback_) {
        ani_ref fnReturnVal;
        if ((status = env->FunctionalObject_Call(
            static_cast<ani_fn_object>(paramGuard->webInitedCallback_), 0, {}, &fnReturnVal)) != ANI_OK) {
            WVLOG_E("UvWebInitedCallbackThreadWoker callback execute failed status : %{public}d", status);
            env->DestroyLocalScope();
            return;
        }
    } else {
        WVLOG_E("webInitedCallback_ is nullptr");
        env->DestroyLocalScope();
        return;
    }
    env->DestroyLocalScope();
    return;
}
} // namespace

WebInitedCallbackParam::WebInitedCallbackParam(ani_env* env, ani_ref callback)
    : vm_(nullptr), webInitedCallback_(nullptr)
{
    WVLOG_D("enter WebInitedCallbackParam");
    if (!env || !callback) {
        WVLOG_E("env or callback is nullptr");
        return;
    }
    if (env->GetVM(&vm_) != ANI_OK) {
        WVLOG_E("get vm from env error");
        return;
    }
    if (env->GlobalReference_Create(callback, &webInitedCallback_)!= ANI_OK) {
        WVLOG_E("create reference obj fail");
        return;
    }
}

WebInitedCallbackParam::~WebInitedCallbackParam()
{
    WVLOG_D("~WebInitedCallbackParam start");
    ani_env* env = GetEnv();
    if (env && webInitedCallback_) {
        if (env->GlobalReference_Delete(webInitedCallback_) != ANI_OK) {
            WVLOG_E("delete reference obj fail");
            return;
        }
    } else {
        WVLOG_E("~WebInitedCallbackParam delete ref error");
    }
}

void WebRunInitedCallbackImpl::RunInitedCallback()
{
    WVLOG_D("enter RunInitedCallback");
    if (!param_) {
        WVLOG_E("param_ is null");
        return;
    }
    if (!param_->webInitedCallback_) {
        WVLOG_E("webInitedCallback_ is null");
        return;
    }
    UvWebInitedCallbackThreadWoker(this);
    WVLOG_D("PostTask successful!");
}
} // namespace OHOS::NWeb