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

#ifndef NWEB_WEB_SITE_CONFIG_PARAMS_H
#define NWEB_WEB_SITE_CONFIG_PARAMS_H

#include <string>
#include <vector>

#include "nweb_export.h"

namespace OHOS::NWeb {

enum class NWebWebSiteSource : int32_t {
    WEB_PAGE = 1,
    SERVICE_WORKER = 2,
    DOWNLOAD = 3,
    EXTENSIONS = 4,
    OTHER = 5,
};

/**
 * @brief Page transition type of the navigation, aligned with the ArkTS
 *        PageTransition enum and the engine page transition flags.
 */
enum class NWebPageTransition : int32_t {
    LINK = 0,
    TYPED = 1,
    AUTO_SUBFRAME = 3,
    MANUAL_SUBFRAME = 4,
    AUTO_TOPLEVEL = 6,
    FORM_SUBMIT = 7,
    RELOAD = 8,
    CORE_MASK = 0xFF,
    FORWARD_BACK = 0x01000000,
    FROM_ADDRESS_BAR = 0x02000000,
    FROM_API = 0x08000000,
    CHAIN_START = 0x10000000,
    CHAIN_END = 0x20000000,
    CLIENT_REDIRECT = 0x40000000,
    SERVER_REDIRECT = (-2147483647 - 1),
    IS_REDIRECT_MASK = (-1073741824),
    QUALIFIER_MASK = (-256),
};

class OHOS_NWEB_EXPORT NWebWebSiteConfigParams {
public:
    virtual ~NWebWebSiteConfigParams() = default;

    virtual std::string Url() = 0;

    virtual NWebWebSiteSource Source() = 0;

    virtual bool IsMainFrame() = 0;

    virtual std::string TopFrameUrl() = 0;

    virtual std::vector<std::string> RedirectChain() = 0;

    virtual std::string Referrer() = 0;

    virtual int32_t PageTransition() = 0;

    // Whether the optional field is present. Instance-level callbacks fill all
    // fields (Has*() == true); the static global callback only fills url and
    // source, so Has*() == false for the optional fields and the binding layer
    // must leave them unset (undefined on the ArkTS side).
    virtual bool HasIsMainFrame() = 0;

    virtual bool HasTopFrameUrl() = 0;

    virtual bool HasRedirectChain() = 0;

    virtual bool HasReferrer() = 0;

    virtual bool HasPageTransition() = 0;
};

} // namespace OHOS::NWeb

#endif // NWEB_WEB_SITE_CONFIG_PARAMS_H
