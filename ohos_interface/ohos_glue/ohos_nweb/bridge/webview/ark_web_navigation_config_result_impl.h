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

#ifndef ARK_WEB_NAVIGATION_CONFIG_RESULT_IMPL_H_
#define ARK_WEB_NAVIGATION_CONFIG_RESULT_IMPL_H_
#pragma once

#include <string>

#include "ohos_nweb/include/ark_web_navigation_config_result.h"

namespace OHOS::ArkWeb {

// webview side: implements ArkWebNavigationConfigResult (ArkWeb interface).
// Constructed and filled by the NAPI layer inside the OnQueryNavigationConfig callback,
// then returned to webcore across the .so boundary.
class ArkWebNavigationConfigResultImpl : public ArkWebNavigationConfigResult {
    IMPLEMENT_REFCOUNTING(ArkWebNavigationConfigResultImpl);

public:
    ArkWebNavigationConfigResultImpl() = default;
    ~ArkWebNavigationConfigResultImpl() override { ArkWebStringStructRelease(user_agent_); }

    void SetUserAgent(const ArkWebString& user_agent) override { user_agent_ = user_agent; }
    void SetViewportWidth(int32_t viewport_width) override { viewport_width_ = viewport_width; }

    // Returns a newly allocated independent buffer owned by the caller; safe to call repeatedly
    // and never shares or releases the buffer owned by the member user_agent_ itself.
    ArkWebString GetUserAgent() override
    {
        return ArkWebStringClassToStruct(ArkWebStringStructToClass(user_agent_));
    }
    int32_t GetViewportWidth() override { return viewport_width_; }

private:
    ArkWebString user_agent_;
    int32_t viewport_width_ = 0;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_NAVIGATION_CONFIG_RESULT_IMPL_H_
