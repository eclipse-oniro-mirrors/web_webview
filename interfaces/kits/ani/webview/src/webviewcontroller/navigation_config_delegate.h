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

#ifndef OHOS_NWEB_ANI_NAVIGATION_CONFIG_DELEGATE_H
#define OHOS_NWEB_ANI_NAVIGATION_CONFIG_DELEGATE_H

#include <memory>

#include <ani.h>

#include "nweb_navigation_config.h"
#include "nweb_query_navigation_config_callback.h"

namespace OHOS {
namespace NWeb {

// Callback delegate for QUERY mode: the engine side invokes OnQueryNavigationConfig,
// and the app side queries the UA and viewport width through the ANI callback.
class NavigationConfigDelegate : public NWebQueryNavigationConfigCallback {
public:
    explicit NavigationConfigDelegate(ani_vm* vm, ani_fn_object callback);
    ~NavigationConfigDelegate() override;

    std::shared_ptr<NWebNavigationConfigResult> OnQueryNavigationConfig(
        std::shared_ptr<NWebNavigationConfigParams> params) override;

    void SetCallback(ani_fn_object callback);

private:
    ani_vm* vm_ = nullptr;
    ani_ref callback_ = nullptr;
};

} // namespace NWeb
} // namespace OHOS

#endif // OHOS_NWEB_ANI_NAVIGATION_CONFIG_DELEGATE_H
