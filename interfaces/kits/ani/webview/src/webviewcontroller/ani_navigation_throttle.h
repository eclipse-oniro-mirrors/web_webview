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
#ifndef OHOS_NWEB_ANI_NAVIGATION_THROTTLE_H
#define OHOS_NWEB_ANI_NAVIGATION_THROTTLE_H

#include <ani.h>

#include "nweb.h"

namespace OHOS {
namespace NWeb {

ani_status StsNavigationThrottleInit(ani_env* env);

// Registered as the native implementation of WebviewController.setNavigationThrottle
// in ani_webview_controller.cpp. Defined in ani_navigation_throttle.cpp.
void AniSetNavigationThrottle(ani_env* env, ani_object object, ani_ref throttleRef);

} // namespace NWeb
} // namespace OHOS
#endif // OHOS_NWEB_ANI_NAVIGATION_THROTTLE_H
