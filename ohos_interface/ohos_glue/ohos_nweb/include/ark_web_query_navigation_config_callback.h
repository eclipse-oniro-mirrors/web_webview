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

#ifndef ARK_WEB_QUERY_NAVIGATION_CONFIG_CALLBACK_H_
#define ARK_WEB_QUERY_NAVIGATION_CONFIG_CALLBACK_H_
#pragma once

#include "base/include/ark_web_base_ref_counted.h"
#include "ohos_nweb/include/ark_web_navigation_config_params.h"
#include "ohos_nweb/include/ark_web_navigation_config_result.h"

namespace OHOS::ArkWeb {

// Callback interface for QUERY mode (across .so boundary).
// Takes an ArkWebNavigationConfigParams pointer and returns an ArkWebNavigationConfigResult pointer.
// Returning nullptr means the app does not handle it and the engine falls back to SET mode.
/*--ark web(source=webview)--*/
class ArkWebQueryNavigationConfigCallback : public virtual ArkWebBaseRefCounted {
public:
    /*--ark web()--*/
    virtual ArkWebRefPtr<ArkWebNavigationConfigResult> OnQueryNavigationConfig(
        ArkWebRefPtr<ArkWebNavigationConfigParams> params) = 0;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_QUERY_NAVIGATION_CONFIG_CALLBACK_H_
