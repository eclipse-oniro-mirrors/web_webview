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
#include "ohos_nweb/bridge/ark_web_web_site_config_callback_wrapper.h"
#include "base/bridge/ark_web_bridge_macros.h"
#include "ohos_nweb/bridge/ark_web_web_site_config_params_impl.h"

#include "ohos_nweb/bridge/ark_web_web_site_config_result_wrapper.h"


namespace OHOS::ArkWeb {

ArkWebWebSiteConfigCallbackWrapper::ArkWebWebSiteConfigCallbackWrapper(ArkWebRefPtr<ArkWebWebSiteConfigCallback> ref)
    : ctocpp_(ref) {}

std::shared_ptr<OHOS::NWeb::NWebWebSiteConfigResult> ArkWebWebSiteConfigCallbackWrapper::QueryWebSiteConfig(
    std::shared_ptr<OHOS::NWeb::NWebWebSiteConfigParams> params)
{
    if (CHECK_SHARED_PTR_IS_NULL(params)) {
        return nullptr;
    }
    ArkWebRefPtr<ArkWebWebSiteConfigResult> ark_result =
        ctocpp_->QueryWebSiteConfig(new ArkWebWebSiteConfigParamsImpl(params));
    if (CHECK_REF_PTR_IS_NULL(ark_result)) {
        return nullptr;
    }
    return std::make_shared<ArkWebWebSiteConfigResultWrapper>(ark_result);
}


} // namespace OHOS::ArkWeb
