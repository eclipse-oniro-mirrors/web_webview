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
#ifndef ARK_WEB_WEB_SITE_CONFIG_RESULT_IMPL_H
#define ARK_WEB_WEB_SITE_CONFIG_RESULT_IMPL_H
#include "ohos_nweb/include/ark_web_web_site_config_result.h"
#include "include/nweb_web_site_config_result.h"
#include "base/include/ark_web_base_ref_counted.h"

namespace OHOS::ArkWeb {

class ArkWebWebSiteConfigResultImpl : public ArkWebWebSiteConfigResult {
public:
    explicit ArkWebWebSiteConfigResultImpl(std::shared_ptr<OHOS::NWeb::NWebWebSiteConfigResult> ref);
    ~ArkWebWebSiteConfigResultImpl() = default;

    ArkWebString UserAgent() override;
    int32_t ViewportWidth() override;

private:
    std::shared_ptr<OHOS::NWeb::NWebWebSiteConfigResult> real_;
    IMPLEMENT_REFCOUNTING(ArkWebWebSiteConfigResultImpl);
};
} // namespace OHOS::ArkWeb
#endif // ARK_WEB_WEB_SITE_CONFIG_RESULT_IMPL_H
