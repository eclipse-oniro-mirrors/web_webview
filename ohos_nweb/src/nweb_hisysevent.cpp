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
#include "hisysevent.h"
#include "nweb_hisysevent.h"

namespace OHOS::NWeb {
namespace {
const HiviewDFX::HiSysEvent::EventType EVENT_TYPES[] = {
    OHOS::HiviewDFX::HiSysEvent::EventType::FAULT,
    OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
    OHOS::HiviewDFX::HiSysEvent::EventType::SECURITY,
    OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
};

enum EventType {
    FAULT = 0,
    STATISTIC,
    SECURITY,
    BEHAVIOR,
};
}

constexpr char INSTANCE_INITIALIZE_TIME[] = "INSTANCE_INITIALIZE_TIME";
constexpr char INSTANCE_ID[] = "INSTANCE_ID";
constexpr char USED_TIME[] = "USED_TIME";

static std::string g_currentBundleName = "";
template<typename... Args>
static int ForwardToHiSysEvent(const std::string& eventName, EventType type, const std::tuple<Args...>& tp)
{
    if (g_currentBundleName.empty()) {
        auto appInfo = AbilityRuntime::ApplicationContext::GetInstance()->GetApplicationInfo();
        if (appInfo != nullptr) {
            g_currentBundleName = appInfo->bundleName.c_str();
        }
    }
    std::tuple<const std::string, const std::string> sysData("BUNDLE_NAME", g_currentBundleName.c_str());
    auto mergeData = std::tuple_cat(sysData, tp);

    return std::apply(
        [&](auto&&... args) {
            return HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::WEBVIEW, eventName, EVENT_TYPES[type], args...);
        },
        mergeData);
}

int EventReport::ReportCreateWebInstanceTime(uint32_t nwebId, int64_t usedTime)
{
    auto data = std::make_tuple(INSTANCE_ID, nwebId, USED_TIME, usedTime);
    return ForwardToHiSysEvent(INSTANCE_INITIALIZE_TIME, STATISTIC, data);
}
} // namespace OHOS::NWeb