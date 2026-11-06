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

#ifndef ARK_WEB_NAVIGATION_CONFIG_PARAMS_WRAPPER_H_
#define ARK_WEB_NAVIGATION_CONFIG_PARAMS_WRAPPER_H_
#pragma once

#include <string>
#include <vector>

#include "ohos_nweb/include/ark_web_navigation_config_params.h"
#include "include/nweb_navigation_config.h"

namespace OHOS::ArkWeb {

// webview side: implements NWebNavigationConfigParams (NWeb C++ interface),
// holding the ArkWebRefPtr<ArkWebNavigationConfigParams> passed from webcore internally.
// Reads ArkWeb fields via getters and converts them to NWeb C++ types for the NAPI layer.
class ArkWebNavigationConfigParamsWrapper : public OHOS::NWeb::NWebNavigationConfigParams {
public:
    explicit ArkWebNavigationConfigParamsWrapper(
        ArkWebRefPtr<ArkWebNavigationConfigParams> ark_params)
        : ark_params_(std::move(ark_params)) {}
    ~ArkWebNavigationConfigParamsWrapper() = default;

    const std::string& GetUrl() const override;
    const std::vector<std::string>& GetRedirectChain() const override;
    const std::string& GetReferrer() const override;
    int32_t GetPageTransition() const override;
    bool GetIsMainFrame() const override;

private:
    ArkWebRefPtr<ArkWebNavigationConfigParams> ark_params_;
    mutable std::string url_cache_;
    mutable std::vector<std::string> redirect_chain_cache_;
    mutable std::string referrer_cache_;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_NAVIGATION_CONFIG_PARAMS_WRAPPER_H_
