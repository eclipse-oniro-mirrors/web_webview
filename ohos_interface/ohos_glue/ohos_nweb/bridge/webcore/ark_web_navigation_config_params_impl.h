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

#ifndef ARK_WEB_NAVIGATION_CONFIG_PARAMS_IMPL_H_
#define ARK_WEB_NAVIGATION_CONFIG_PARAMS_IMPL_H_
#pragma once

#include <memory>

#include "ohos_nweb/include/ark_web_navigation_config_params.h"
#include "include/nweb_navigation_config.h"

namespace OHOS::ArkWeb {

// webcore side: implements ArkWebNavigationConfigParams (ArkWeb interface),
// holding a NWeb C++ NWebNavigationConfigParams pointer internally.
// Constructed by webcore and passed to the webview callback across the .so boundary.
class ArkWebNavigationConfigParamsImpl : public ArkWebNavigationConfigParams {
    IMPLEMENT_REFCOUNTING(ArkWebNavigationConfigParamsImpl);

public:
    explicit ArkWebNavigationConfigParamsImpl(
        std::shared_ptr<OHOS::NWeb::NWebNavigationConfigParams> nweb_params)
        : nweb_params_(std::move(nweb_params)) {}
    ~ArkWebNavigationConfigParamsImpl() = default;

    ArkWebString GetUrl() override;
    ArkWebStringVector GetRedirectChain() override;
    ArkWebString GetReferrer() override;
    int32_t GetPageTransition() override;
    bool GetIsMainFrame() override;

private:
    std::shared_ptr<OHOS::NWeb::NWebNavigationConfigParams> nweb_params_;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_NAVIGATION_CONFIG_PARAMS_IMPL_H_
