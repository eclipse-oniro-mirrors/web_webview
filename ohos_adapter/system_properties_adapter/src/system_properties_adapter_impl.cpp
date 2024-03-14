/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "system_properties_adapter_impl.h"

#include <securec.h>

#include "init_param.h"
#include "nweb_adapter_helper.h"
#include "nweb_log.h"
#include "parameter.h"
#include "parameters.h"
#include "sysversion.h"

namespace OHOS::NWeb {
const std::string FACTORY_CONFIG_VALUE = "factoryConfig";
const std::string FACTORY_LEVEL_VALUE = "factoryLevel";
const std::string FACTORY_LEVEL_WATCH = "16";
const std::string FACTORY_LEVEL_PC = "8";
const std::string FACTORY_LEVEL_TABLET = "4";
const std::string FACTORY_LEVEL_PHONE = "2";
const std::string FACTORY_LEVEL_DEFAULT = "1";
// static
SystemPropertiesAdapterImpl& SystemPropertiesAdapterImpl::GetInstance()
{
    static SystemPropertiesAdapterImpl instance;
    return instance;
}

SystemPropertiesAdapterImpl::SystemPropertiesAdapterImpl()
{
    std::string osFullName =
        OHOS::system::GetParameter("const.ohos.fullname", "");
    if (osFullName.empty()) {
        WVLOG_E("get os full name failed");
        return;
    }
    int versionPartOne;
    int versionPartTwo;
    int versionPartThree;
    int versionPartFour;
    const char* tmp = strstr(osFullName.c_str(), "-");
    if (tmp == NULL) {
        return;
    }
    tmp++;
    int ret = sscanf_s(tmp, "%d.%d.%d.%d",
        &versionPartOne, &versionPartTwo, &versionPartThree, &versionPartFour);
    if (ret <= 0) {
        WVLOG_E("paser os full name failed");
        return;
    }
    softwareMajorVersion_ = versionPartOne;
    softwareSeniorVersion_ = versionPartTwo;
}

bool SystemPropertiesAdapterImpl::GetResourceUseHapPathEnable()
{
    return OHOS::system::GetBoolParameter("compress", false);
}

std::string SystemPropertiesAdapterImpl::GetDeviceInfoProductModel()
{
    return GetProductModel();
}

std::string SystemPropertiesAdapterImpl::GetDeviceInfoBrand()
{
    return GetBrand();
}

int32_t SystemPropertiesAdapterImpl::GetDeviceInfoMajorVersion()
{
    return GetMajorVersion();
}

ProductDeviceType SystemPropertiesAdapterImpl::GetProductDeviceType()
{
    std::string factoryLevel = NWebAdapterHelper::Instance().
        ParsePerfConfig(FACTORY_CONFIG_VALUE, FACTORY_LEVEL_VALUE);
    if (factoryLevel.empty()) {
        NWebAdapterHelper::Instance().ReadConfigIfNeeded();
        factoryLevel = NWebAdapterHelper::Instance().
            ParsePerfConfig(FACTORY_CONFIG_VALUE, FACTORY_LEVEL_VALUE);
    }
    WVLOG_D("read config factoryLevel: %{public}s ", factoryLevel.c_str());
    if (factoryLevel == FACTORY_LEVEL_PHONE || factoryLevel == FACTORY_LEVEL_DEFAULT) {
        return ProductDeviceType::DEVICE_TYPE_MOBILE;
    } else if (factoryLevel == FACTORY_LEVEL_TABLET) {
        return ProductDeviceType::DEVICE_TYPE_TABLET;
    } else if (factoryLevel == FACTORY_LEVEL_PC) {
        return ProductDeviceType::DEVICE_TYPE_2IN1;
    }
    return ProductDeviceType::DEVICE_TYPE_UNKNOWN;
}

bool SystemPropertiesAdapterImpl::GetWebOptimizationValue()
{
    return OHOS::system::GetBoolParameter("web.optimization", true);
}

bool SystemPropertiesAdapterImpl::GetLockdownModeStatus()
{
    char buffer[32] = { 0 };
    uint32_t buffSize = sizeof(buffer);

    if (SystemGetParameter("ohos.boot.advsecmode.state", buffer, &buffSize) == 0 && strcmp(buffer, "0") != 0) {
        return true;
    }
    return false;
}

std::string SystemPropertiesAdapterImpl::GetUserAgentOSName()
{
    return OHOS::system::GetParameter("const.product.os.dist.name", "");
}

int32_t SystemPropertiesAdapterImpl::GetSoftwareMajorVersion()
{
    return softwareMajorVersion_;
}

int32_t SystemPropertiesAdapterImpl::GetSoftwareSeniorVersion()
{
    return softwareSeniorVersion_;
}

std::string SystemPropertiesAdapterImpl::GetNetlogMode()
{
    return OHOS::system::GetParameter("web.debug.netlog", "");
}

bool SystemPropertiesAdapterImpl::GetTraceDebugEnable()
{
    return OHOS::system::GetBoolParameter("web.debug.trace", false);
}

std::string SystemPropertiesAdapterImpl::GetSiteIsolationMode()
{
    return OHOS::system::GetParameter("web.debug.strictsiteIsolation.enable", "");
}
} // namespace OHOS::NWeb
