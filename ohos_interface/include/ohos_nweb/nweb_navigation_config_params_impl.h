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

#ifndef NWEB_NAVIGATION_CONFIG_PARAMS_IMPL_H
#define NWEB_NAVIGATION_CONFIG_PARAMS_IMPL_H

#include <string>
#include <utility>
#include <vector>

#include "nweb_navigation_config.h"

namespace OHOS::NWeb {

// Simple concrete implementation of NWebNavigationConfigParams in the NWeb C++ layer.
// Used by the engine side; does not cross the .so boundary.
class NWebNavigationConfigParamsImpl : public NWebNavigationConfigParams {
public:
    NWebNavigationConfigParamsImpl(std::string url,
                                   std::vector<std::string> redirect_chain,
                                   std::string referrer,
                                   int32_t page_transition,
                                   bool is_main_frame)
        : url_(std::move(url)),
          redirect_chain_(std::move(redirect_chain)),
          referrer_(std::move(referrer)),
          page_transition_(page_transition),
          is_main_frame_(is_main_frame) {}
    ~NWebNavigationConfigParamsImpl() = default;

    const std::string& GetUrl() const override { return url_; }
    const std::vector<std::string>& GetRedirectChain() const override { return redirect_chain_; }
    const std::string& GetReferrer() const override { return referrer_; }
    int32_t GetPageTransition() const override { return page_transition_; }
    bool GetIsMainFrame() const override { return is_main_frame_; }

private:
    std::string url_;
    std::vector<std::string> redirect_chain_;
    std::string referrer_;
    int32_t page_transition_;
    bool is_main_frame_;
};

}  // namespace OHOS::NWeb

#endif  // NWEB_NAVIGATION_CONFIG_PARAMS_IMPL_H
