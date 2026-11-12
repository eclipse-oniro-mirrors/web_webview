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

#ifndef ARK_WEB_NAVIGATION_CONFIG_RESULT_H_
#define ARK_WEB_NAVIGATION_CONFIG_RESULT_H_
#pragma once

#include "base/include/ark_web_base_ref_counted.h"
#include "ohos_nweb/include/ark_web_nweb_structs.h"

namespace OHOS::ArkWeb {

// Output interface (across .so boundary): constructed and returned by the app side inside
// OnQueryNavigationConfig, the engine reads the result via getters.
// The field layout is hidden inside the .so, so adding fields does not break the ABI.
/*--ark web(source=webview)--*/
class ArkWebNavigationConfigResult : public virtual ArkWebBaseRefCounted {
public:
    /*--ark web()--*/
    virtual void SetUserAgent(const ArkWebString& user_agent) = 0;

    /*--ark web()--*/
    virtual void SetViewportWidth(int32_t viewport_width) = 0;

    /*--ark web()--*/
    virtual ArkWebString GetUserAgent() = 0;

    /*--ark web()--*/
    virtual int32_t GetViewportWidth() = 0;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_NAVIGATION_CONFIG_RESULT_H_
