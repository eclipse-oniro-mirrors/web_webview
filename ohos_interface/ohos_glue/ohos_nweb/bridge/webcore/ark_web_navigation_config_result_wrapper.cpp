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

#include "ohos_nweb/bridge/ark_web_navigation_config_result_wrapper.h"

#include "base/bridge/ark_web_bridge_macros.h"

namespace OHOS::ArkWeb {

void ArkWebNavigationConfigResultWrapper::SetUserAgent(const std::string& user_agent)
{
    if (ark_result_) {
        ark_result_->SetUserAgent(ArkWebStringClassToStruct(user_agent));
    }
}

void ArkWebNavigationConfigResultWrapper::SetViewportWidth(int32_t viewport_width)
{
    if (ark_result_) {
        ark_result_->SetViewportWidth(viewport_width);
    }
}

const std::string& ArkWebNavigationConfigResultWrapper::GetUserAgent() const
{
    if (ark_result_) {
        ArkWebString st_ua = ark_result_->GetUserAgent();
        user_agent_cache_ = ArkWebStringStructToClass(st_ua);
        ArkWebStringStructRelease(st_ua);
    }
    return user_agent_cache_;
}

int32_t ArkWebNavigationConfigResultWrapper::GetViewportWidth() const
{
    if (ark_result_) {
        return ark_result_->GetViewportWidth();
    }
    return 0;
}

} // namespace OHOS::ArkWeb
