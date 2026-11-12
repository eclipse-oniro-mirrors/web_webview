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

#ifndef ARK_WEB_NAVIGATION_CONFIG_RESULT_WRAPPER_H_
#define ARK_WEB_NAVIGATION_CONFIG_RESULT_WRAPPER_H_
#pragma once

#include <string>

#include "ohos_nweb/include/ark_web_navigation_config_result.h"
#include "include/nweb_navigation_config.h"

namespace OHOS::ArkWeb {

// webcore side: implements NWebNavigationConfigResult (NWeb C++ interface),
// holding the ArkWebRefPtr<ArkWebNavigationConfigResult> returned by webview internally.
// Reads ArkWeb fields via getters and converts them to NWeb C++ types.
class ArkWebNavigationConfigResultWrapper : public OHOS::NWeb::NWebNavigationConfigResult {
public:
    explicit ArkWebNavigationConfigResultWrapper(
        ArkWebRefPtr<ArkWebNavigationConfigResult> ark_result)
        : ark_result_(std::move(ark_result)) {}
    ~ArkWebNavigationConfigResultWrapper() = default;

    void SetUserAgent(const std::string& user_agent) override;
    void SetViewportWidth(int32_t viewport_width) override;
    const std::string& GetUserAgent() const override;
    int32_t GetViewportWidth() const override;

private:
    ArkWebRefPtr<ArkWebNavigationConfigResult> ark_result_;
    mutable std::string user_agent_cache_;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_NAVIGATION_CONFIG_RESULT_WRAPPER_H_
