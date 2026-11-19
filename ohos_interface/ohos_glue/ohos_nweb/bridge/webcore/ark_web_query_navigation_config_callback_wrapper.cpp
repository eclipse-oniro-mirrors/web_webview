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

#include "ohos_nweb/bridge/ark_web_query_navigation_config_callback_wrapper.h"

#include "ohos_nweb/bridge/ark_web_navigation_config_params_impl.h"
#include "ohos_nweb/bridge/ark_web_navigation_config_result_wrapper.h"

#include "base/bridge/ark_web_bridge_macros.h"

namespace OHOS::ArkWeb {

ArkWebQueryNavigationConfigCallbackWrapper::ArkWebQueryNavigationConfigCallbackWrapper(
    ArkWebRefPtr<ArkWebQueryNavigationConfigCallback> ark_web_query_navigation_config_callback)
    : ark_web_query_navigation_config_callback_(ark_web_query_navigation_config_callback)
{}

std::shared_ptr<OHOS::NWeb::NWebNavigationConfigResult>
ArkWebQueryNavigationConfigCallbackWrapper::OnQueryNavigationConfig(
    std::shared_ptr<OHOS::NWeb::NWebNavigationConfigParams> params)
{
    if (CHECK_REF_PTR_IS_NULL(ark_web_query_navigation_config_callback_)) {
        return nullptr;
    }

    ArkWebRefPtr<ArkWebNavigationConfigParams> ark_params = nullptr;
    if (!CHECK_SHARED_PTR_IS_NULL(params)) {
        ark_params = new ArkWebNavigationConfigParamsImpl(params);
    }

    ArkWebRefPtr<ArkWebNavigationConfigResult> ark_result =
        ark_web_query_navigation_config_callback_->OnQueryNavigationConfig(ark_params);
    if (CHECK_REF_PTR_IS_NULL(ark_result)) {
        return nullptr;
    }

    return std::make_shared<ArkWebNavigationConfigResultWrapper>(ark_result);
}

} // namespace OHOS::ArkWeb
