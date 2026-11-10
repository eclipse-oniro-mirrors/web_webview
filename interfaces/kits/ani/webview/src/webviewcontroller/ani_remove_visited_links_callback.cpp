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
#include "event_handler.h"
#include "event_runner.h"

namespace OHOS {
namespace NWeb {
namespace {
const std::string REMOVE_VISITED_LINKS_TASK_ID = "removeVisitedLinksSince";
} // namespace

AniRemoveVisitedLinksCallback::AniRemoveVisitedLinksCallback(ani_env* env, ani_resolver resolver)
    : env_(env), resolver_(resolver) {}

void AniRemoveVisitedLinksCallback::OnRemoveComplete()
{
    if (!env_) {
        WVLOG_E("env is nullptr");
        return;
    }
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
    auto task = [env, resolver]() {
        ani_ref resultRef = nullptr;
        if (env->GetUndefined(&resultRef) != ANI_OK) {
            WVLOG_E("GetUndefined failed, rejecting promise to avoid pending state");
            ani_ref jsError = NWebError::AniBusinessError::CreateError(env, NWebError::INIT_ERROR);
            if (env->PromiseResolver_Reject(resolver, reinterpret_cast<ani_error>(jsError)) != ANI_OK) {
                WVLOG_E("PromiseResolver_Reject failed after GetUndefined failure");
            }
            return;
        }
        if (env->PromiseResolver_Resolve(resolver, resultRef) != ANI_OK) {
            WVLOG_E("PromiseResolver_Resolve failed");
        }
    };
    if (!handler->PostTask(std::move(task), REMOVE_VISITED_LINKS_TASK_ID, 0,
        OHOS::AppExecFwk::EventQueue::Priority::HIGH, {})) {
        WVLOG_E("PostTask failed for removeVisitedLinksSince callback");
    }
}

} // namespace NWeb
} // namespace OHOS
