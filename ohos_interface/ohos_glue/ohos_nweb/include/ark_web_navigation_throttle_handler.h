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

#ifndef ARK_WEB_NAVIGATION_THROTTLE_HANDLER_H_
#define ARK_WEB_NAVIGATION_THROTTLE_HANDLER_H_
#pragma once

#include "base/include/ark_web_base_ref_counted.h"
#include "base/include/ark_web_types.h"
#include "ohos_nweb/include/ark_web_navigation_throttle_info.h"

namespace OHOS::ArkWeb {

/*--ark web(source=webview)--*/
class ArkWebNavigationThrottleHandler : public virtual ArkWebBaseRefCounted {
public:
    /**
     * @brief Called when a navigation reaches an intercepted stage.
     *
     * @param stage The stage of the navigation. Mirrors OHOS::NWeb::NWebThrottleStage
     *        (WILL_START_REQUEST = 0, WILL_REDIRECT_REQUEST = 1, WILL_PROCESS_RESPONSE = 2,
     *        WILL_FAIL_REQUEST = 3).
     * @param info The navigation information for the current stage. Field availability varies by stage.
     * @param deferId The identifier of the defer handle. Valid only when DEFER is returned; pass it to
     *        ArkWebNWeb::ResolveNavigationDefer to resume or cancel the deferred navigation.
     * @return The action to take on the navigation. Mirrors OHOS::NWeb::NWebThrottleAction
     *         (PROCEED = 0, CANCEL = 1, DEFER = 2).
     */
    /*--ark web()--*/
    virtual int32_t OnThrottleEvent(int32_t stage, ArkWebRefPtr<ArkWebNavigationThrottleInfo> info,
        uint64_t deferId) = 0;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_NAVIGATION_THROTTLE_HANDLER_H_
