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

#include "nweb_user_agent_builder.h"

#include <cstdint>
#include <string>

#include "nweb_log.h"
#include "ohos_adapter_helper.h"

namespace OHOS::NWeb {

namespace {

// Kernel-compatible device type token values (GetOhosFullname in
// arkweb_user_agent_ext.cc compares the compatible device type against these).
const char* const DEVICE_TYPE_PHONE = "Phone";
const char* const DEVICE_TYPE_PC = "PC";
const char* const DEVICE_TYPE_TABLET = "Tablet";

// Kernel fallback OS name when const.ohos.fullname cannot be parsed.
const char* const DEFAULT_OS_NAME = "OpenHarmony";

std::string BuildOsInfo(const std::string& deviceType, const std::string& osName,
    int32_t osMajorVersion, int32_t osSeniorVersion)
{
    if (osName.empty() || osMajorVersion == -1 || osSeniorVersion == -1) {
        return deviceType + "; " + DEFAULT_OS_NAME;
    }
    return deviceType + "; " + osName + " " + std::to_string(osMajorVersion) + "." +
        std::to_string(osSeniorVersion);
}

std::string ResolveDeviceTypeToken(const std::string& compatibleDeviceType)
{
    if (compatibleDeviceType == DEVICE_TYPE_PHONE || compatibleDeviceType == DEVICE_TYPE_PC ||
        compatibleDeviceType == DEVICE_TYPE_TABLET) {
        return compatibleDeviceType;
    }
    return DEVICE_TYPE_PHONE;
}

bool ShouldAppendMobile(ProductDeviceType productDeviceType, const std::string& compatibleDeviceType)
{
    if (productDeviceType == ProductDeviceType::DEVICE_TYPE_MOBILE) {
        return true;
    }
    if ((productDeviceType == ProductDeviceType::DEVICE_TYPE_TABLET ||
            productDeviceType == ProductDeviceType::DEVICE_TYPE_2IN1) &&
        compatibleDeviceType == DEVICE_TYPE_PHONE) {
        return true;
    }
    return false;
}

} // namespace

std::string UserAgentBuilder::BuildUserAgentLite(const UserAgentLiteParams& params)
{
    std::string userAgent = "Mozilla/5.0 (" +
        BuildOsInfo(params.deviceType, params.osName, params.osMajorVersion, params.osSeniorVersion) +
        ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + params.chromeCompatibleVersion +
        ".0.0.0 Safari/537.36  ArkWeb/" + params.arkWebVersion;
    if (params.appendMobile) {
        userAgent += " Mobile";
    }
    return userAgent;
}

ArkWeb::ArkWebVersionResolveResult UserAgentBuilder::BuildDefaultUserAgentLite(std::string& userAgent)
{
    userAgent.clear();
    std::string arkWebVersion;
    ArkWeb::ArkWebVersionResolveResult resolveResult =
        ArkWeb::GetArkWebVersionStringFromEngine(arkWebVersion);
    if (resolveResult != ArkWeb::ArkWebVersionResolveResult::OK || arkWebVersion.empty()) {
        WVLOG_E("failed to resolve arkweb version for user agent lite, result=%{public}d",
            static_cast<int32_t>(resolveResult));
        return resolveResult;
    }

    SystemPropertiesAdapter& properties = OhosAdapterHelper::GetInstance().GetSystemPropertiesInstance();
    std::string compatibleDeviceType = properties.GetCompatibleDeviceType();
    std::string deviceType = ResolveDeviceTypeToken(compatibleDeviceType);
    bool appendMobile = ShouldAppendMobile(properties.GetProductDeviceType(), compatibleDeviceType);
    std::string chromeCompatibleVersion = ArkWeb::GetChromeCompatibleVersionStringFromEngine();
    if (chromeCompatibleVersion.empty()) {
        WVLOG_E("failed to resolve chrome compatible version for user agent lite");
        return ArkWeb::ArkWebVersionResolveResult::SYMBOL_NOT_FOUND;
    }
    UserAgentLiteParams params;
    params.deviceType = deviceType;
    params.osName = properties.GetUserAgentBaseOSName();
    params.osMajorVersion = properties.GetSoftwareMajorVersion();
    params.osSeniorVersion = properties.GetSoftwareSeniorVersion();
    params.chromeCompatibleVersion = chromeCompatibleVersion;
    params.arkWebVersion = arkWebVersion;
    params.appendMobile = appendMobile;
    userAgent = BuildUserAgentLite(params);
    return ArkWeb::ArkWebVersionResolveResult::OK;
}

std::string UserAgentBuilder::BuildDefaultUserAgentLite()
{
    std::string userAgent;
    BuildDefaultUserAgentLite(userAgent);
    return userAgent;
}

} // namespace OHOS::NWeb
