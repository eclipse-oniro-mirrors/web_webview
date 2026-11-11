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

#ifndef NWEB_WEB_SITE_CONFIG_CALLBACK_H
#define NWEB_WEB_SITE_CONFIG_CALLBACK_H

#include <memory>

#include "nweb_export.h"
#include "nweb_web_site_config_params.h"
#include "nweb_web_site_config_result.h"

namespace OHOS::NWeb {

class OHOS_NWEB_EXPORT NWebWebSiteConfigCallback {
public:
    virtual ~NWebWebSiteConfigCallback() = default;

    virtual std::shared_ptr<NWebWebSiteConfigResult> QueryWebSiteConfig(
        std::shared_ptr<NWebWebSiteConfigParams> params) = 0;
};

} // namespace OHOS::NWeb

#endif // NWEB_WEB_SITE_CONFIG_CALLBACK_H
