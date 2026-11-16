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

#include "ark_web_navigation_throttle_handler_wrapper.h"

#include "base/bridge/ark_web_bridge_macros.h"
#include "ohos_nweb/bridge/ark_web_navigation_throttle_info_impl.h"

namespace OHOS::ArkWeb {

ArkWebNavigationThrottleHandlerWrapper::ArkWebNavigationThrottleHandlerWrapper(
    ArkWebRefPtr<ArkWebNavigationThrottleHandler> ark_web_handler)
    : ark_web_handler_(ark_web_handler)
{}

OHOS::NWeb::NWebThrottleAction ArkWebNavigationThrottleHandlerWrapper::OnThrottleEvent(
    OHOS::NWeb::NWebThrottleStage stage, const OHOS::NWeb::NWebNavigationThrottleInfo& info, uint64_t deferId)
{
    if (!ark_web_handler_) {
        return OHOS::NWeb::NWebThrottleAction::PROCEED;
    }
    ArkWebRefPtr<ArkWebNavigationThrottleInfo> arkWebInfo = new ArkWebNavigationThrottleInfoImpl(info);
    int32_t action = ark_web_handler_->OnThrottleEvent(
        static_cast<int32_t>(stage), arkWebInfo, deferId);
    return static_cast<OHOS::NWeb::NWebThrottleAction>(action);
}

} // namespace OHOS::ArkWeb
