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
#include "ohos_nweb/bridge/ark_web_web_site_config_callback_impl.h"
#include "base/include/ark_web_types.h"
#include "base/bridge/ark_web_bridge_macros.h"
#include "ohos_nweb/bridge/ark_web_web_site_config_params_wrapper.h"
#include "ohos_nweb/bridge/ark_web_web_site_config_result_impl.h"

namespace OHOS::ArkWeb {

ArkWebWebSiteConfigCallbackImpl::ArkWebWebSiteConfigCallbackImpl(
    std::shared_ptr<OHOS::NWeb::NWebWebSiteConfigCallback> ref) : real_(ref) {}

ArkWebRefPtr<ArkWebWebSiteConfigResult> ArkWebWebSiteConfigCallbackImpl::QueryWebSiteConfig(
    ArkWebRefPtr<ArkWebWebSiteConfigParams> params)
{
    if (CHECK_REF_PTR_IS_NULL(params)) {
        return nullptr;
    }

    std::shared_ptr<OHOS::NWeb::NWebWebSiteConfigResult> result =
        real_->QueryWebSiteConfig(std::make_shared<ArkWebWebSiteConfigParamsWrapper>(params));
    if (CHECK_SHARED_PTR_IS_NULL(result)) {
        return nullptr;
    }
    return new ArkWebWebSiteConfigResultImpl(result);
}


} // namespace OHOS::ArkWeb
