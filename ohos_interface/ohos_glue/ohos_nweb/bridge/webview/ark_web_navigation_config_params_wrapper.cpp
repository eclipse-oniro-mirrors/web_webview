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

#include "ohos_nweb/bridge/ark_web_navigation_config_params_wrapper.h"

#include "base/bridge/ark_web_bridge_macros.h"

namespace OHOS::ArkWeb {

const std::string& ArkWebNavigationConfigParamsWrapper::GetUrl() const
{
    if (ark_params_) {
        ArkWebString st_url = ark_params_->GetUrl();
        url_cache_ = ArkWebStringStructToClass(st_url);
        ArkWebStringStructRelease(st_url);
    }
    return url_cache_;
}

const std::vector<std::string>& ArkWebNavigationConfigParamsWrapper::GetRedirectChain() const
{
    if (ark_params_) {
        ArkWebStringVector st_chain = ark_params_->GetRedirectChain();
        redirect_chain_cache_ = ArkWebStringVectorStructToClass(st_chain);
        ArkWebStringVectorStructRelease(st_chain);
    }
    return redirect_chain_cache_;
}

const std::string& ArkWebNavigationConfigParamsWrapper::GetReferrer() const
{
    if (ark_params_) {
        ArkWebString st_ref = ark_params_->GetReferrer();
        referrer_cache_ = ArkWebStringStructToClass(st_ref);
        ArkWebStringStructRelease(st_ref);
    }
    return referrer_cache_;
}

int32_t ArkWebNavigationConfigParamsWrapper::GetPageTransition() const
{
    if (ark_params_) {
        return ark_params_->GetPageTransition();
    }
    return 0;
}

bool ArkWebNavigationConfigParamsWrapper::GetIsMainFrame() const
{
    if (ark_params_) {
        return ark_params_->GetIsMainFrame();
    }
    return false;
}

} // namespace OHOS::ArkWeb
