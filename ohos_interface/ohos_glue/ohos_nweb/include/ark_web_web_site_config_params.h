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

#ifndef ARK_WEB_WEB_SITE_CONFIG_PARAMS_H_
#define ARK_WEB_WEB_SITE_CONFIG_PARAMS_H_
#pragma once

#include "base/include/ark_web_base_ref_counted.h"
#include "base/include/ark_web_types.h"

namespace OHOS::ArkWeb {

/*--ark web(source=webcore)--*/
class ArkWebWebSiteConfigParams : public virtual ArkWebBaseRefCounted {
public:
    /*--ark web()--*/
    virtual ArkWebString Url() = 0;

    /*--ark web()--*/
    virtual int32_t Source() = 0;

    /*--ark web()--*/
    virtual bool IsMainFrame() = 0;

    /*--ark web()--*/
    virtual ArkWebString TopFrameUrl() = 0;

    /*--ark web()--*/
    virtual ArkWebStringVector RedirectChain() = 0;

    /*--ark web()--*/
    virtual ArkWebString Referrer() = 0;

    /*--ark web()--*/
    virtual int32_t PageTransition() = 0;

    /*--ark web()--*/
    virtual bool HasIsMainFrame() = 0;

    /*--ark web()--*/
    virtual bool HasTopFrameUrl() = 0;

    /*--ark web()--*/
    virtual bool HasRedirectChain() = 0;

    /*--ark web()--*/
    virtual bool HasReferrer() = 0;

    /*--ark web()--*/
    virtual bool HasPageTransition() = 0;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_WEB_SITE_CONFIG_PARAMS_H_
