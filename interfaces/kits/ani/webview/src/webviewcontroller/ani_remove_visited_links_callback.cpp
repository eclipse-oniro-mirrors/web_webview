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

#include "ani_business_error.h"
#include "web_errors.h"
#include "event_handler.h"
#include "event_runner.h"

namespace OHOS {
namespace NWeb {
namespace {
const std::string REMOVE_VISITED_LINKS_TASK_ID = "removeVisitedLinksSince";
} // namespace

AniRemoveVisitedLinksCallback::AniRemoveVisitedLinksCallback(ani_env* env, ani_resolver resolver)
    : resolver_(resolver)
{
    if (env == nullptr) {
        WVLOG_E("env is nullptr");
        return;
    }
    ani_status status = env->GetVM(&vm_);
    if (status != ANI_OK) {
        vm_ = nullptr;
        WVLOG_E("GetVM failed, status=%{public}d", static_cast<int>(status));
        return;
    }
}

void AniRemoveVisitedLinksCallback::OnRemoveComplete()
{
    if (!mainHandler_) {
        std::shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::GetMainEventRunner();
        if (!runner) {
            WVLOG_E("get main event runner failed");
            return;
        }
        if (runner->IsCurrentRunnerThread()) {
            ResolvePromise();
            return;
        }
        mainHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
        if (!mainHandler_) {
            WVLOG_E("create event handler failed");
            return;
        }
    }

    auto sharedThis = shared_from_this();
    auto task = [sharedThis]() { sharedThis->ResolvePromise(); };
    if (!mainHandler_->PostTask(std::move(task), REMOVE_VISITED_LINKS_TASK_ID, 0,
        AppExecFwk::EventQueue::Priority::HIGH, {})) {
        WVLOG_E("PostTask failed for removeVisitedLinksSince callback");
    }
}

void AniRemoveVisitedLinksCallback::ResolvePromise()
{
    if (vm_ == nullptr || resolver_ == nullptr) {
        WVLOG_E("vm or resolver is nullptr");
        return;
    }

    ani_env* env = nullptr;
    if (vm_->GetEnv(ANI_VERSION_1, &env) != ANI_OK || env == nullptr) {
        WVLOG_E("GetEnv failed");
        return;
    }

    ani_ref resultRef = nullptr;
    if (env->GetUndefined(&resultRef) != ANI_OK) {
        WVLOG_E("GetUndefined failed, rejecting promise to avoid pending state");
        ani_ref jsError = NWebError::AniBusinessError::CreateError(env, NWebError::INIT_ERROR);
        if (env->PromiseResolver_Reject(resolver_, reinterpret_cast<ani_error>(jsError)) != ANI_OK) {
            WVLOG_E("PromiseResolver_Reject failed after GetUndefined failure");
        }
        return;
    }
    if (env->PromiseResolver_Resolve(resolver_, resultRef) != ANI_OK) {
        WVLOG_E("PromiseResolver_Resolve failed");
    }
}

} // namespace NWeb
} // namespace OHOS
