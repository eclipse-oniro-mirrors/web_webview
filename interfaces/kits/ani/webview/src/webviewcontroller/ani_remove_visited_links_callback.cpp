/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "ani_remove_visited_links_callback.h"

#include "event_handler.h"
#include "event_runner.h"

namespace OHOS {
namespace NWeb {

namespace {

const std::string VISITED_LINKS_CALLBACK_TASK_ID = "removeVisitedLinksSince";

void ResolveOnMainThread(ani_env* env, ani_resolver resolver)
{
    if (!env) {
        return;
    }
    ani_ref resultRef = nullptr;
    if (env->GetUndefined(&resultRef) != ANI_OK) {
        WVLOG_E("GetUndefined failed");
        return;
    }
    if (env->PromiseResolver_Resolve(resolver, resultRef) != ANI_OK) {
        WVLOG_E("PromiseResolver_Resolve failed");
    }
}

} // namespace

void AniRemoveVisitedLinksCallback::OnRemoveComplete()
{
    if (!env_) {
        WVLOG_E("env is nullptr");
        return;
    }
    // Marshal to the main event loop thread; calling PromiseResolver_Resolve
    // from a non-main thread risks crashing the ANI VM (same pattern as
    // NWebConfigCookieCallbackImpl in ani_web_cookie_manager.cpp).
    auto runner = OHOS::AppExecFwk::EventRunner::GetMainEventRunner();
    if (!runner) {
        WVLOG_E("get main event runner failed");
        return;
    }
    auto handler = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    if (!handler) {
        WVLOG_E("create event handler failed");
        return;
    }
    ani_env* env = env_;
    ani_resolver resolver = resolver_;
    auto task = [env, resolver]() { ResolveOnMainThread(env, resolver); };
    bool posted = handler->PostTask(std::move(task), VISITED_LINKS_CALLBACK_TASK_ID, 0,
        OHOS::AppExecFwk::EventQueue::Priority::HIGH, {});
    if (!posted) {
        WVLOG_E("PostTask failed for removeVisitedLinksSince callback");
    }
}

} // namespace NWeb
} // namespace OHOS
