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

const std::string PROP_RENDER_DUMP = "web.render.dump";
const std::string PROP_HITRACE_ENABLEFLAGS = "debug.hitrace.tags.enableflags";
const std::unordered_map<std::string, PropertiesKey> PROP_KEY_MAP = {
    {PROP_RENDER_DUMP, PropertiesKey::PROP_RENDER_DUMP},
    {PROP_HITRACE_ENABLEFLAGS, PropertiesKey::PROP_HITRACE_ENABLEFLAGS}};

void SystemPropertiesChangeCallback(const char* key, const char* value, void* context) {
    WVLOG_D("sys prop change key: %{public}s ,value : %{public}s ", key,  value);
    SystemPropertiesAdapterImpl::GetInstance().DispatchAllWatcherInfo(key, value);
}

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
    AddAllSysPropWatchers();
}

SystemPropertiesAdapterImpl::~SystemPropertiesAdapterImpl()
{
    RemoveAllSysPropWatchers();
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
    ProductDeviceType factoryLevel = AnalysisFromConfig();
    if (factoryLevel != ProductDeviceType::DEVICE_TYPE_UNKNOWN) {
        return factoryLevel;
    }
    WVLOG_W("read config factoryLevel: fail");
    // RK or other device cant read config，need read from system deviceType
    std::string deviceType = OHOS::system::GetDeviceType();
    if (deviceType == "phone" || deviceType == "default") {
        return ProductDeviceType::DEVICE_TYPE_MOBILE;
    } else if (deviceType == "tablet") {
        return ProductDeviceType::DEVICE_TYPE_TABLET;
    } else if (deviceType == "2in1") {
        return ProductDeviceType::DEVICE_TYPE_2IN1;
    }
    return ProductDeviceType::DEVICE_TYPE_UNKNOWN;
}

ProductDeviceType SystemPropertiesAdapterImpl::AnalysisFromConfig()
{
    std::string factoryLevel = NWebAdapterHelper::Instance()
        .ParsePerfConfig(FACTORY_CONFIG_VALUE, FACTORY_LEVEL_VALUE);
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

bool SystemPropertiesAdapterImpl::IsAdvancedSecurityMode()
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

bool SystemPropertiesAdapterImpl::GetOOPGPUEnable()
{
    if (OHOS::system::GetParameter("web.oop.gpu", "") == "false") {
        return false;
    }
    return true;
}

void SystemPropertiesAdapterImpl::SetOOPGPUDisable()
{
    if (OHOS::system::GetParameter("web.oop.gpu", "") == "None") {
        OHOS::system::SetParameter("web.oop.gpu", "false");
    }
    return;
}

int32_t SystemPropertiesAdapterImpl::GetFlowBufMaxFd()
{
    return OHOS::system::GetIntParameter("web.flowbuffer.maxfd", -1);
}

void SystemPropertiesAdapterImpl::AddAllSysPropWatchers()
{
    for (auto &item : PROP_KEY_MAP) {
        auto errNo =  WatchParameter(item.first.c_str(), SystemPropertiesChangeCallback, nullptr);
        if (errNo == 0) {
            sysPropObserver_[item.second];
            sysPropMutex_[item.second];
        } else {
            WVLOG_E("add watch error result: %{public}d", errNo);
        }
    }
}

void SystemPropertiesAdapterImpl::RemoveAllSysPropWatchers()
{
    for (auto &item : PROP_KEY_MAP) {
        auto errNo = RemoveParameterWatcher(item.first.c_str(), nullptr, nullptr);
        if (errNo != 0) {
            WVLOG_E("remove watch error result: %{public}d", errNo);
        }
    }
}

void SystemPropertiesAdapterImpl::DispatchAllWatcherInfo(const char* key, const char* value)
{
    auto propKeyIt = PROP_KEY_MAP.find(key);
    if (propKeyIt == PROP_KEY_MAP.end()) {
        WVLOG_E("sys prop change key is invalid: %{public}s", key);
        return;
    }

    PropertiesKey propkey = propKeyIt->second;
    auto& keyObservers = sysPropObserver_[propkey];

    if (keyObservers.size() == 0) {
        WVLOG_E("no observers in this key: %{public}s", key);
        return;
    }

    std::shared_lock lock(sysPropMutex_[propkey]);
    for (auto &item : keyObservers) {
        item->PropertiesUpdate(value);
    }
}

void SystemPropertiesAdapterImpl::AttachSysPropObserver(PropertiesKey key, SystemPropertiesObserver* observer)
{
    auto observerIt = sysPropObserver_.find(key);
    if (observerIt == sysPropObserver_.end()) {
        WVLOG_E("properties key invalid in attach");
        return;
    }

    if (observer == nullptr) {
        WVLOG_E("properties key observer invalid in attach");
        return;
    }

    std::vector<SystemPropertiesObserver*>& observerVec = observerIt->second;
    std::unique_lock lock(sysPropMutex_[key]);
    observerVec.push_back(observer);
}

void SystemPropertiesAdapterImpl::DetachSysPropObserver(PropertiesKey key, SystemPropertiesObserver* observer)
{
    auto observerIt = sysPropObserver_.find(key);
    if (observerIt == sysPropObserver_.end()) {
        WVLOG_E("properties key invalid in detach");
        return;
    }

    if (observer == nullptr) {
        WVLOG_E("properties key observer invalid in detach");
        return;
    }

    std::vector<SystemPropertiesObserver*>& observerVec = observerIt->second;
    std::unique_lock lock(sysPropMutex_[key]);

    auto it = std::find(observerVec.begin(), observerVec.end(), observer);
    if (it != observerVec.end()) {
        observerVec.erase(it);
    }
}

bool SystemPropertiesAdapterImpl::GetBoolParameter(const std::string& key, bool defaultValue)
{
    return OHOS::system::GetBoolParameter(key, defaultValue);
}

std::vector<FrameRateSetting> SystemPropertiesAdapterImpl::GetLTPOConfig(const std::string& settingName)
{
    return NWebAdapterHelper::Instance().
        GetPerfConfig(settingName);
}
} // namespace OHOS::NWeb
