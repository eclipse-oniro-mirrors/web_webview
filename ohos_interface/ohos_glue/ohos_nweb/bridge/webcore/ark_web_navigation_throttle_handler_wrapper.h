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

#ifndef ARK_WEB_NAVIGATION_THROTTLE_HANDLER_WRAPPER_H_
#define ARK_WEB_NAVIGATION_THROTTLE_HANDLER_WRAPPER_H_
#pragma once

#include "include/nweb.h"
#include "ohos_nweb/include/ark_web_navigation_throttle_handler.h"

namespace OHOS::ArkWeb {

class ArkWebNavigationThrottleHandlerWrapper : public OHOS::NWeb::NWebNavigationThrottleHandler {
public:
    ArkWebNavigationThrottleHandlerWrapper(ArkWebRefPtr<ArkWebNavigationThrottleHandler> ark_web_handler);
    ~ArkWebNavigationThrottleHandlerWrapper() = default;

    /**
     * @brief Called when a navigation reaches an intercepted stage.
     *
     * @param stage The stage of the navigation.
     * @param info The navigation information for the current stage.
     * @param deferId The identifier of the defer handle. It is valid only when NWebThrottleAction::DEFER is
     *        returned; pass it to NWeb::ResolveNavigationDefer to resume or cancel the deferred navigation.
     * @return The action to take on the navigation.
     */
    OHOS::NWeb::NWebThrottleAction OnThrottleEvent(OHOS::NWeb::NWebThrottleStage stage,
        const OHOS::NWeb::NWebNavigationThrottleInfo& info, uint64_t deferId) override;

private:
    ArkWebRefPtr<ArkWebNavigationThrottleHandler> ark_web_handler_;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_NAVIGATION_THROTTLE_HANDLER_WRAPPER_H_
