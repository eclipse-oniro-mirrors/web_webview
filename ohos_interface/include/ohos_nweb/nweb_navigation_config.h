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

#ifndef NWEB_NAVIGATION_CONFIG_H
#define NWEB_NAVIGATION_CONFIG_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace OHOS::NWeb {

enum class WebNavigationConfigMode { SET = 0, QUERY = 1 };

// Input interface: constructed and filled by the engine side, read-only for the app side.
// As a pure virtual class, the field layout no longer enters the ABI and can evolve freely inside the .so.
class NWebNavigationConfigParams {
public:
    virtual ~NWebNavigationConfigParams() = default;

    virtual const std::string& GetUrl() const = 0;
    virtual const std::vector<std::string>& GetRedirectChain() const = 0;
    virtual const std::string& GetReferrer() const = 0;
    virtual int32_t GetPageTransition() const = 0;
    virtual bool GetIsMainFrame() const = 0;
};

// Output interface: the caller (engine side) constructs an empty object which is returned
// to the app side to fill in. The app writes fields via setters, the engine reads via getters.
class NWebNavigationConfigResult {
public:
    virtual ~NWebNavigationConfigResult() = default;

    virtual void SetUserAgent(const std::string& user_agent) = 0;
    virtual void SetViewportWidth(int32_t viewport_width) = 0;

    virtual const std::string& GetUserAgent() const = 0;
    virtual int32_t GetViewportWidth() const = 0;
};

}  // namespace OHOS::NWeb

#endif  // NWEB_NAVIGATION_CONFIG_H
