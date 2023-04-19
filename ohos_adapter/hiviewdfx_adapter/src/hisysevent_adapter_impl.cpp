/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "hisysevent_adapter_impl.h"

#include "hisysevent.h"

namespace OHOS::NWeb {
namespace {
const HiviewDFX::HiSysEvent::EventType EVENT_TYPES[] = {
    OHOS::HiviewDFX::HiSysEvent::EventType::FAULT,
    OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
    OHOS::HiviewDFX::HiSysEvent::EventType::SECURITY,
    OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
};

template<typename... Args>
int ForwardToHiSysEvent(const std::string& eventName, HiSysEventAdapter::EventType type, const std::tuple<Args...>& tp)
{
    return std::apply(
        [&](auto&&... args) {
            return HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::WEBVIEW, eventName, EVENT_TYPES[type], args...);
        },
        tp);
}
} // namespace

HiSysEventAdapterImpl& HiSysEventAdapterImpl::GetInstance()
{
    static HiSysEventAdapterImpl instance;
    return instance;
}

int HiSysEventAdapterImpl::Write(const std::string& eventName, EventType type,
    const std::tuple<const std::string, const int, const std::string, const int, const std::string, const int,
        const std::string, const int, const std::string, const float>& data)
{
    return ForwardToHiSysEvent(eventName, type, data);
}

int HiSysEventAdapterImpl::Write(const std::string& eventName, EventType type,
    const std::tuple<const std::string, const int, const std::string, const int, const std::string, const int>& data)
{
    return ForwardToHiSysEvent(eventName, type, data);
}

int HiSysEventAdapterImpl::Write(const std::string& eventName, EventType type,
    const std::tuple<const std::string, const int, const std::string, const std::string, const std::string, const int,
        const std::string, const std::string>& data)
{
    return ForwardToHiSysEvent(eventName, type, data);
}
} // namespace OHOS::NWeb
