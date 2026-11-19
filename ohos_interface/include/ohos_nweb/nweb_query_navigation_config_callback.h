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

#ifndef NWEB_QUERY_NAVIGATION_CONFIG_CALLBACK_H
#define NWEB_QUERY_NAVIGATION_CONFIG_CALLBACK_H

#include <memory>

#include "nweb_navigation_config.h"

namespace OHOS::NWeb {

// Callback interface for QUERY mode: invoked by the engine side, implemented by the app side.
//
// Takes a NWebNavigationConfigParams pointer (constructed by the engine, read-only for the app)
// and returns a NWebNavigationConfigResult pointer (constructed and filled by the app, consumed
// by the engine). Returning nullptr means the app does not handle it and the engine falls back
// to SET mode.
class NWebQueryNavigationConfigCallback {
public:
    virtual ~NWebQueryNavigationConfigCallback() = default;

    virtual std::shared_ptr<NWebNavigationConfigResult> OnQueryNavigationConfig(
        std::shared_ptr<NWebNavigationConfigParams> params) = 0;
};

}  // namespace OHOS::NWeb

#endif  // NWEB_QUERY_NAVIGATION_CONFIG_CALLBACK_H
