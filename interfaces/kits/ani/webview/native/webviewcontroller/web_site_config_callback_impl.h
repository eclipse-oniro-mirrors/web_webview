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

#ifndef ANI_WEB_SITE_CONFIG_CALLBACK_IMPL_H
#define ANI_WEB_SITE_CONFIG_CALLBACK_IMPL_H

#include <ani.h>
#include <memory>
#include <string>

#include "nweb_web_site_config_callback.h"
#include "nweb_web_site_config_params.h"
#include "nweb_web_site_config_result.h"

namespace OHOS::NWeb {

class AniNWebWebSiteConfigResultImpl : public NWebWebSiteConfigResult {
public:
    AniNWebWebSiteConfigResultImpl(const std::string& userAgent, int32_t viewportWidth)
        : userAgent_(userAgent), viewportWidth_(viewportWidth) {}
    ~AniNWebWebSiteConfigResultImpl() override = default;

    std::string UserAgent() override { return userAgent_; }
    int32_t ViewportWidth() override { return viewportWidth_; }

private:
    std::string userAgent_;
    int32_t viewportWidth_ = 0;
};

class AniNWebWebSiteConfigCallbackImpl : public NWebWebSiteConfigCallback {
public:
    explicit AniNWebWebSiteConfigCallbackImpl(ani_vm* vm, ani_fn_object callback);
    ~AniNWebWebSiteConfigCallbackImpl() override;

    std::shared_ptr<NWebWebSiteConfigResult> QueryWebSiteConfig(
        std::shared_ptr<NWebWebSiteConfigParams> params) override;

private:
    ani_object ConstructParams(std::shared_ptr<NWebWebSiteConfigParams> params);
    bool ParseResult(ani_ref result, std::shared_ptr<NWebWebSiteConfigResult>& out);

    ani_vm* vm_ = nullptr;
    ani_ref callback_ = nullptr;
};

} // namespace OHOS::NWeb

#endif // ANI_WEB_SITE_CONFIG_CALLBACK_IMPL_H
