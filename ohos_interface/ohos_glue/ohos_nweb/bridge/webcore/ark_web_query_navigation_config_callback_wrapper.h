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

#ifndef ARK_WEB_QUERY_NAVIGATION_CONFIG_CALLBACK_WRAPPER_H_
#define ARK_WEB_QUERY_NAVIGATION_CONFIG_CALLBACK_WRAPPER_H_
#pragma once

#include "include/nweb_query_navigation_config_callback.h"
#include "ohos_nweb/include/ark_web_query_navigation_config_callback.h"

namespace OHOS::ArkWeb {

class ArkWebQueryNavigationConfigCallbackWrapper : public OHOS::NWeb::NWebQueryNavigationConfigCallback {
public:
    ArkWebQueryNavigationConfigCallbackWrapper(
        ArkWebRefPtr<ArkWebQueryNavigationConfigCallback> ark_web_query_navigation_config_callback);
    ~ArkWebQueryNavigationConfigCallbackWrapper() = default;

    std::shared_ptr<OHOS::NWeb::NWebNavigationConfigResult> OnQueryNavigationConfig(
        std::shared_ptr<OHOS::NWeb::NWebNavigationConfigParams> params) override;

private:
    ArkWebRefPtr<ArkWebQueryNavigationConfigCallback> ark_web_query_navigation_config_callback_;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_QUERY_NAVIGATION_CONFIG_CALLBACK_WRAPPER_H_
