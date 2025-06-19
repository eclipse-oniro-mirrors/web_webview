/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "ability_manager_client.h"
#include "application_context.h"
#include "hisysevent_adapter_impl.h"
#include "hisysevent.h"
#include "ohos_resource_adapter_impl.h"

namespace OHOS::NWeb {
namespace {
const HiviewDFX::HiSysEvent::EventType EVENT_TYPES[] = {
    OHOS::HiviewDFX::HiSysEvent::EventType::FAULT,
    OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
    OHOS::HiviewDFX::HiSysEvent::EventType::SECURITY,
    OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
};
}

const static std::string KEY_LISTS[] = {
    "NAVIGATION_ID",
    "NAVIGATION_START",
    "REDIRECT_COUNT",
    "REDIRECT_START",
    "REDIRECT_END",
    "FETCH_START",
    "WORKER_START",
    "DOMAIN_LOOKUP_START",
    "DOMAIN_LOOKUP_END",
    "CONNECT_START",
    "SECURE_CONNECT_START",
    "CONNECT_END",
    "REQUESR_START",
    "RESPONSE_START",
    "RESPONSE_END",
    "DOM_INTERACTIVE",
    "DOM_CONTENT_LOADED_EVENT_START",
    "DOM_CONTENT_LOADED_EVENT_END",
    "LOAD_EVENT_START",
    "LOAD_EVENT_END",
    "FIRST_PAINT",
    "FIRST_CONTENTFUL_PAINT",
    "LARGEST_CONTENTFUL_PAINT",
    "RENDER_INIT_BLOCK",
};
static std::string g_currentBundleName = "";
static std::string g_versionCode = "";
HiSysEventAdapterImpl& HiSysEventAdapterImpl::GetInstance()
{
    static HiSysEventAdapterImpl instance;
    return instance;
}

template<typename... Args>
static int ForwardToHiSysEvent(const std::string& eventName, HiSysEventAdapter::EventType type,
    const std::tuple<Args...>& tp)
{
    if (g_currentBundleName.empty()) {
        auto appInfo = AbilityRuntime::ApplicationContext::GetInstance()->GetApplicationInfo();
        if (appInfo != nullptr) {
            g_currentBundleName = appInfo->bundleName.c_str();
        }
    }
    if (g_versionCode.empty()) {
        g_versionCode = OhosResourceAdapterImpl::GetArkWebVersion();
    }
    std::tuple<const std::string, const std::string, const std::string, const std::string> sysData(
        "BUNDLE_NAME", g_currentBundleName.c_str(),
        "VERSION_CODE", g_versionCode.c_str()
    );
    auto mergeData = std::tuple_cat(sysData, tp);

    return std::apply(
        [&](auto&&... args) {
            return HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::WEBVIEW, eventName, EVENT_TYPES[type], args...);
        },
        mergeData);
}

int HiSysEventAdapterImpl::Write(const std::string& eventName, EventType type,
    const std::tuple<const std::string, const std::string>& data)
{
    std::string targetType = "PAGE_LOAD_TIME";
    if (eventName == targetType) {
        auto appInfo = AbilityRuntime::ApplicationContext::GetInstance()->GetApplicationInfo();
        if (appInfo == nullptr) {
            return -1;
        }
        AppExecFwk::ElementName elementName = AAFwk::AbilityManagerClient::GetInstance()->GetTopAbility();

        std::tuple<const std::string, const std::string> sysData = {
            "ABILITY_NAME", elementName.GetAbilityName(),
        };

        const std::string input = std::get<0>(data);

        const std::int64_t value1 = GetValue(input, KEY_LISTS[0], KEY_LISTS[1]);
        const std::int64_t value2 = GetValue(input, KEY_LISTS[1], KEY_LISTS[2]);
        const std::uint32_t value3 = (std::uint32_t)GetValue(input, KEY_LISTS[2], KEY_LISTS[3]);
        const std::int64_t value4 = GetValue(input, KEY_LISTS[3], KEY_LISTS[4]);
        const std::int64_t value5 = GetValue(input, KEY_LISTS[4], KEY_LISTS[5]);
        const std::int64_t value6 = GetValue(input, KEY_LISTS[5], KEY_LISTS[6]);
        const std::int64_t value7 = GetValue(input, KEY_LISTS[6], KEY_LISTS[7]);
        const std::int64_t value8 = GetValue(input, KEY_LISTS[7], KEY_LISTS[8]);
        const std::int64_t value9 = GetValue(input, KEY_LISTS[8], KEY_LISTS[9]);
        const std::int64_t value10 = GetValue(input, KEY_LISTS[9], KEY_LISTS[10]);
        const std::int64_t value11 = GetValue(input, KEY_LISTS[10], KEY_LISTS[11]);
        const std::int64_t value12 = GetValue(input, KEY_LISTS[11], KEY_LISTS[12]);
        const std::int64_t value13 = GetValue(input, KEY_LISTS[12], KEY_LISTS[13]);
        const std::int64_t value14 = GetValue(input, KEY_LISTS[13], KEY_LISTS[14]);
        const std::int64_t value15 = GetValue(input, KEY_LISTS[14], KEY_LISTS[15]);
        const std::int64_t value16 = GetValue(input, KEY_LISTS[15], KEY_LISTS[16]);
        const std::int64_t value17 = GetValue(input, KEY_LISTS[16], KEY_LISTS[17]);
        const std::int64_t value18 = GetValue(input, KEY_LISTS[17], KEY_LISTS[18]);
        const std::int64_t value19 = GetValue(input, KEY_LISTS[18], KEY_LISTS[19]);
        const std::int64_t value20 = GetValue(input, KEY_LISTS[19], KEY_LISTS[20]);
        const std::int64_t value21 = GetValue(input, KEY_LISTS[20], KEY_LISTS[21]);
        const std::int64_t value22 = GetValue(input, KEY_LISTS[21], KEY_LISTS[22]);
        const std::int64_t value23 = GetValue(input, KEY_LISTS[22], KEY_LISTS[23]);
        const std::int64_t value24 = GetValue(input, KEY_LISTS[23], "");

        auto newData = std::make_tuple(
            KEY_LISTS[0], value1, KEY_LISTS[1], value2, KEY_LISTS[2], value3, KEY_LISTS[3], value4,
            KEY_LISTS[4], value5, KEY_LISTS[5], value6, KEY_LISTS[6], value7, KEY_LISTS[7], value8,
            KEY_LISTS[8], value9, KEY_LISTS[9], value10, KEY_LISTS[10], value11, KEY_LISTS[11], value12, 
            KEY_LISTS[12], value13, KEY_LISTS[13], value14, KEY_LISTS[14], value15, KEY_LISTS[15], value16, 
            KEY_LISTS[16], value17, KEY_LISTS[17], value18, KEY_LISTS[18], value19, KEY_LISTS[19], value20, 
            KEY_LISTS[20], value21, KEY_LISTS[21], value22, KEY_LISTS[22], value23, KEY_LISTS[23], value24);
            
        auto mergeData = std::tuple_cat(newData, sysData);
        return ForwardToHiSysEvent(eventName, type, mergeData);
    }
    return ForwardToHiSysEvent(eventName, type, data);
}

int HiSysEventAdapterImpl::Write(const std::string& eventName, EventType type,
    const std::tuple<const std::string, const std::string, const std::string, const std::string>& data)
{
    return ForwardToHiSysEvent(eventName, type, data);
}

int HiSysEventAdapterImpl::Write(const std::string& eventName, EventType type,
    const std::tuple<const std::string, const std::string, const std::string, const std::string,
                     const std::string, const std::string>& data)
{
    return ForwardToHiSysEvent(eventName, type, data);
}

int HiSysEventAdapterImpl::Write(const std::string& eventName, EventType type,
    const std::tuple<const std::string, const std::string, const std::string, const std::string,
                     const std::string, const std::string, const std::string, const std::string>& data)
{
    return ForwardToHiSysEvent(eventName, type, data);
}

int HiSysEventAdapterImpl::Write(const std::string& eventName, EventType type,
    const std::tuple<const std::string, const std::string, const std::string, const std::string,
                     const std::string, const std::string, const std::string, const std::string,
                     const std::string, const std::string>& data)
{
    return ForwardToHiSysEvent(eventName, type, data);
}

int HiSysEventAdapterImpl::Write(const std::string& eventName, EventType type,
    const std::tuple<const std::string, const std::string, const std::string, const std::string,
                     const std::string, const std::string, const std::string, const std::string,
                     const std::string, const std::string, const std::string, const std::string>& data)
{
    return ForwardToHiSysEvent(eventName, type, data);
}

using systemData = std::tuple<const std::string, const int, const std::string, const std::string,
                              const std::string, const std::string>;

int HiSysEventAdapterImpl::Write(const std::string& eventName, EventType type,
    const std::tuple<const std::string, const int64_t, const std::string, const int,
    const std::string, const std::vector<uint16_t>, const std::string, const int>& data)
{
    auto appInfo = AbilityRuntime::ApplicationContext::GetInstance()->GetApplicationInfo();
    if (appInfo == nullptr) {
        return -1;
    }
    AppExecFwk::ElementName elementName = AAFwk::AbilityManagerClient::GetInstance()->GetTopAbility();

    systemData sysData = {
        "VERSION_CODE", appInfo->versionCode,
        "VERSION_NAME", appInfo->versionName.c_str(),
        "ABILITY_NAME", elementName.GetAbilityName()
    };

    auto mergeData = std::tuple_cat(data, sysData);
    return ForwardToHiSysEvent(eventName, type, mergeData);
}

int HiSysEventAdapterImpl::Write(const std::string& eventName, EventType type,
    const std::tuple<const std::string, const int64_t, const std::string, const int64_t,
    const std::string, const int, const std::string, const int,
    const std::string, const int64_t, const std::string, const int>& data)
{
    auto appInfo = AbilityRuntime::ApplicationContext::GetInstance()->GetApplicationInfo();
    if (appInfo == nullptr) {
        return -1;
    }
    AppExecFwk::ElementName elementName = AAFwk::AbilityManagerClient::GetInstance()->GetTopAbility();

    std::tuple<const std::string, const std::string, const std::string, const std::string,
        const std::string, const std::string> sysData = {
        "SCENE_ID", "WEB_LIST_FLING",
        "ABILITY_NAME", elementName.GetAbilityName(),
        "PAGE_URL", ""
    };

    auto mergeData = std::tuple_cat(data, sysData);
    return ForwardToHiSysEvent(eventName, type, mergeData);
}

int HiSysEventAdapterImpl::Write(const std::string& eventName, EventType type,
    const std::tuple<const std::string, const int64_t,
    const std::string, const int64_t, const std::string, const uint32_t,
    const std::string, const int64_t, const std::string, const int64_t,
    const std::string, const int64_t, const std::string, const int64_t,
    const std::string, const int64_t, const std::string, const int64_t,
    const std::string, const int64_t, const std::string, const int64_t,
    const std::string, const int64_t, const std::string, const int64_t,
    const std::string, const int64_t, const std::string, const int64_t,
    const std::string, const int64_t, const std::string, const int64_t,
    const std::string, const int64_t, const std::string, const int64_t,
    const std::string, const int64_t, const std::string, const int64_t,
    const std::string, const int64_t, const std::string, const int64_t>& data)
{
    auto appInfo = AbilityRuntime::ApplicationContext::GetInstance()->GetApplicationInfo();
    if (appInfo == nullptr) {
        return -1;
    }
    AppExecFwk::ElementName elementName = AAFwk::AbilityManagerClient::GetInstance()->GetTopAbility();

    std::tuple<const std::string, const std::string> sysData = {
        "ABILITY_NAME", elementName.GetAbilityName(),
    };

    auto mergeData = std::tuple_cat(data, sysData);
    return ForwardToHiSysEvent(eventName, type, mergeData);
}

int HiSysEventAdapterImpl::Write(const std::string& eventName, EventType type,
    const std::tuple<const std::string, const std::string, const std::string, const std::string,
                     const std::string, const std::string, const std::string, const std::string,
                     const std::string, const std::string, const std::string, const std::string,
                     const std::string, const std::string>& data)
{
    return ForwardToHiSysEvent(eventName, type, data);
}

int HiSysEventAdapterImpl::Write(const std::string& eventName, EventType type,
    const std::tuple<const std::string, const std::string, const std::string, const std::string,
                     const std::string, const std::string, const std::string, const std::string,
                     const std::string, const std::string, const std::string, const std::string,
                     const std::string, const std::string, const std::string, const std::string>& data)
{
    std::string versionCode = OhosResourceAdapterImpl::GetArkWebVersion();
    auto extendedData = std::tuple_cat(
        std::make_tuple("VERSION_CODE", versionCode.c_str()),
        data
    );

    return std::apply(
        [&](auto&&... args) {
            return HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::WEBVIEW, eventName, EVENT_TYPES[type], args...);
        },
        extendedData);
}

int HiSysEventAdapterImpl::Write(const std::string& eventName, EventType type,
    const std::tuple<const std::string, const uint32_t, const std::string, const uint64_t>& data)
{
    return ForwardToHiSysEvent(eventName, type, data);
}
} // namespace OHOS::NWeb
