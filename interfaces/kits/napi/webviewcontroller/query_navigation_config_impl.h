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

#ifndef QUERY_NAVIGATION_CONFIG_IMPL_H
#define QUERY_NAVIGATION_CONFIG_IMPL_H

#include <memory>
#include <string>
#include <vector>

#include "napi/native_api.h"
#include "nweb_navigation_config.h"
#include "nweb_navigation_config_result_impl.h"
#include "nweb_query_navigation_config_callback.h"

namespace OHOS::NWeb {

class NWebQueryNavigationConfigCallbackImpl : public NWebQueryNavigationConfigCallback {
public:
    NWebQueryNavigationConfigCallbackImpl(int32_t nwebId, napi_env env, napi_ref callback);
    ~NWebQueryNavigationConfigCallbackImpl() override;

    std::shared_ptr<NWebNavigationConfigResult> OnQueryNavigationConfig(
        std::shared_ptr<NWebNavigationConfigParams> params) override;

private:
    void ConstructParams(napi_value* result, NWebNavigationConfigParams& params);
    void ConstructRedirectChain(napi_value* arr, const std::vector<std::string>& chain);
    std::shared_ptr<NWebNavigationConfigResult> ParseResult(napi_value result);

    int32_t nwebId_ = -1;
    napi_env env_ = nullptr;
    napi_ref callback_ = nullptr;
};

}  // namespace OHOS::NWeb

#endif  // QUERY_NAVIGATION_CONFIG_IMPL_H
