/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef NWEB_USER_AGENT_BUILDER_H
#define NWEB_USER_AGENT_BUILDER_H

#include <cstdint>
#include <string>

#include "arkweb_utils.h"

namespace OHOS::NWeb {

struct UserAgentLiteParams {
    std::string deviceType;
    std::string osName;
    int32_t osMajorVersion = -1;
    int32_t osSeniorVersion = -1;
    std::string chromeCompatibleVersion;
    std::string arkWebVersion;
    bool appendMobile = false;
};

class UserAgentBuilder {
public:
    UserAgentBuilder() = delete;

    /**
     * @brief Assembles the UA Lite string from explicit field values.
     *
     * Template (BR-1, byte-identical to the kernel path):
     * Mozilla/5.0 ({DeviceType}; {OSName} {OSVersion}) AppleWebKit/537.36
     * (KHTML, like Gecko) Chrome/{ChromeCompatibleVersion}.0.0.0
     * Safari/537.36  ArkWeb/{ArkWebVersion}{DeviceCompat}
     *
     * Two spaces separate Safari/537.36 and ArkWeb/ (kernel
     * BuildUserAgentFromOSAndProduct + SetProductString concatenation);
     * DeviceCompat is " Mobile" (one leading space) or empty, in which case
     * the string terminates at the ArkWeb version without trailing spaces.
     *
     * When OS info is unavailable (empty osName or version -1), the OS segment
     * falls back to the kernel behavior: "{DeviceType}; OpenHarmony" without
     * a version number.
     */
    static std::string BuildUserAgentLite(const UserAgentLiteParams& params);

    /**
     * @brief Reads system fields via SystemPropertiesAdapter and the ArkWeb
     *        version via the exported engine symbol, then assembles the UA.
     * @return The UA string, or an empty string when the version cannot be
     *         resolved from libarkweb_engine.so.
     */
    static std::string BuildDefaultUserAgentLite();

    /**
     * @brief Detailed overload of BuildDefaultUserAgentLite.
     *
     * @param userAgent Output UA string; empty on any resolution failure.
     * @return OK on success; LIB_OPEN_FAILURE or SYMBOL_NOT_FOUND as reported
     *         by the engine version resolver (mapped to error codes by
     *         upper-layer callers).
     */
    static ArkWeb::ArkWebVersionResolveResult BuildDefaultUserAgentLite(std::string& userAgent);
};

} // namespace OHOS::NWeb

#endif // NWEB_USER_AGENT_BUILDER_H
