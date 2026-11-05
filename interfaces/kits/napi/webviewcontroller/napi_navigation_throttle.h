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

#ifndef NAPI_NAVIGATION_THROTTLE_H
#define NAPI_NAVIGATION_THROTTLE_H

#include <memory>
#include <string>

#include "auto_napi_ref.h"
#include "napi/native_node_api.h"
#include "nweb.h"

namespace OHOS::NWeb {
namespace NapiNavigationThrottle {

// Creates a handler that forwards throttle events to the JavaScript
// NavigationThrottle object. Returns nullptr when the object cannot be
// referenced.
std::shared_ptr<NWebNavigationThrottleHandler> CreateHandler(
    napi_env env, napi_value throttle, int32_t nwebId);

// Returns true when the value is undefined or null (clear semantics).
bool IsClearValue(napi_env env, napi_value value);

}  // namespace NapiNavigationThrottle
}  // namespace OHOS::NWeb

#endif  // NAPI_NAVIGATION_THROTTLE_H
