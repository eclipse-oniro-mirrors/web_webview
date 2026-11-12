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

#ifndef NWEB_NAVIGATION_CONFIG_RESULT_IMPL_H
#define NWEB_NAVIGATION_CONFIG_RESULT_IMPL_H

#include <string>

#include "nweb_navigation_config.h"

namespace OHOS::NWeb {

// Simple concrete implementation of NWebNavigationConfigResult in the NWeb C++ layer.
// Used by the NAPI layer; does not cross the .so boundary.
class NWebNavigationConfigResultImpl : public NWebNavigationConfigResult {
public:
    NWebNavigationConfigResultImpl() = default;
    ~NWebNavigationConfigResultImpl() = default;

    void SetUserAgent(const std::string& user_agent) override { user_agent_ = user_agent; }
    void SetViewportWidth(int32_t viewport_width) override { viewport_width_ = viewport_width; }

    const std::string& GetUserAgent() const override { return user_agent_; }
    int32_t GetViewportWidth() const override { return viewport_width_; }

private:
    std::string user_agent_;
    int32_t viewport_width_ = 0;
};

}  // namespace OHOS::NWeb

#endif  // NWEB_NAVIGATION_CONFIG_RESULT_IMPL_H
