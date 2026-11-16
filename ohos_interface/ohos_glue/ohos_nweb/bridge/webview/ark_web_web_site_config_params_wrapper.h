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
#ifndef ARK_WEB_WEB_SITE_CONFIG_PARAMS_WRAPPER_H
#define ARK_WEB_WEB_SITE_CONFIG_PARAMS_WRAPPER_H
#include "include/nweb_web_site_config_params.h"
#include "ohos_nweb/include/ark_web_web_site_config_params.h"
#include "base/include/ark_web_types.h"
namespace OHOS::ArkWeb {

class ArkWebWebSiteConfigParamsWrapper : public OHOS::NWeb::NWebWebSiteConfigParams {
public:
    explicit ArkWebWebSiteConfigParamsWrapper(ArkWebRefPtr<ArkWebWebSiteConfigParams> ref);
    ~ArkWebWebSiteConfigParamsWrapper() = default;

    std::string Url() override;
    OHOS::NWeb::NWebWebSiteSource Source() override;
    bool IsMainFrame() override;
    std::string TopFrameUrl() override;
    std::vector<std::string> RedirectChain() override;
    std::string Referrer() override;
    int32_t PageTransition() override;
    bool HasIsMainFrame() override;
    bool HasTopFrameUrl() override;
    bool HasRedirectChain() override;
    bool HasReferrer() override;
    bool HasPageTransition() override;

private:
    ArkWebRefPtr<ArkWebWebSiteConfigParams> ctocpp_;
};
} // namespace OHOS::ArkWeb
#endif // ARK_WEB_WEB_SITE_CONFIG_PARAMS_WRAPPER_H
