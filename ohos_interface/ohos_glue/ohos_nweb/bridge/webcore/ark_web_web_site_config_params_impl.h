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
#ifndef ARK_WEB_WEB_SITE_CONFIG_PARAMS_IMPL_H
#define ARK_WEB_WEB_SITE_CONFIG_PARAMS_IMPL_H
#include "ohos_nweb/include/ark_web_web_site_config_params.h"
#include "include/nweb_web_site_config_params.h"
#include "base/include/ark_web_base_ref_counted.h"

namespace OHOS::ArkWeb {

class ArkWebWebSiteConfigParamsImpl : public ArkWebWebSiteConfigParams {
public:
    explicit ArkWebWebSiteConfigParamsImpl(std::shared_ptr<OHOS::NWeb::NWebWebSiteConfigParams> ref);
    ~ArkWebWebSiteConfigParamsImpl() = default;

    ArkWebString Url() override;
    int32_t Source() override;
    bool IsMainFrame() override;
    ArkWebString TopFrameUrl() override;
    ArkWebStringVector RedirectChain() override;
    ArkWebString Referrer() override;
    int32_t PageTransition() override;
    bool HasIsMainFrame() override;
    bool HasTopFrameUrl() override;
    bool HasRedirectChain() override;
    bool HasReferrer() override;
    bool HasPageTransition() override;

private:
    std::shared_ptr<OHOS::NWeb::NWebWebSiteConfigParams> real_;
    IMPLEMENT_REFCOUNTING(ArkWebWebSiteConfigParamsImpl);
};
} // namespace OHOS::ArkWeb
#endif // ARK_WEB_WEB_SITE_CONFIG_PARAMS_IMPL_H
