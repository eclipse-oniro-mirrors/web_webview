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

#ifndef ARK_WEB_NAVIGATION_CONFIG_PARAMS_H_
#define ARK_WEB_NAVIGATION_CONFIG_PARAMS_H_
#pragma once

#include "base/include/ark_web_base_ref_counted.h"
#include "ohos_nweb/include/ark_web_nweb_structs.h"

namespace OHOS::ArkWeb {

// Input interface (across .so boundary): constructed by the engine side, read-only for the app.
// The field layout is hidden inside the .so, so adding fields does not break the ABI.
/*--ark web(source=webcore)--*/
class ArkWebNavigationConfigParams : public virtual ArkWebBaseRefCounted {
public:
    /*--ark web()--*/
    virtual ArkWebString GetUrl() = 0;

    /*--ark web()--*/
    virtual ArkWebStringVector GetRedirectChain() = 0;

    /*--ark web()--*/
    virtual ArkWebString GetReferrer() = 0;

    /*--ark web()--*/
    virtual int32_t GetPageTransition() = 0;

    /*--ark web()--*/
    virtual bool GetIsMainFrame() = 0;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_NAVIGATION_CONFIG_PARAMS_H_
