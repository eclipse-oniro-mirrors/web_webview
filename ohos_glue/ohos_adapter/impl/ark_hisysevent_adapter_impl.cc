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

#include "ark_hisysevent_adapter_impl.h"

namespace OHOS::ArkWeb {

ArkHiSysEventAdapterImpl::ArkHiSysEventAdapterImpl(NWeb::HiSysEventAdapter& ref) : real_(ref) {}

int ArkHiSysEventAdapterImpl::Write(const ArkWebString& eventName, uint32_t type, const ArkWebString key1,
    const int value1, const ArkWebString key2, const int value2, const ArkWebString key3, const int value3,
    const ArkWebString key4, const int value4, const ArkWebString key5, const float value5)
{
    std::string s_eventName = ArkWebStringStructToClass(eventName);
    std::string s_key1 = ArkWebStringStructToClass(key1);
    std::string s_key2 = ArkWebStringStructToClass(key2);
    std::string s_key3 = ArkWebStringStructToClass(key3);
    std::string s_key4 = ArkWebStringStructToClass(key4);
    std::string s_key5 = ArkWebStringStructToClass(key5);
    std::tuple data = std::make_tuple(s_key1, value1, s_key2, value2, s_key3, value3, s_key4, value4, s_key5, value5);

    return real_.Write(s_eventName, (OHOS::NWeb::HiSysEventAdapter::EventType)type, data);
}

int ArkHiSysEventAdapterImpl::Write(const ArkWebString& eventName, uint32_t type, const ArkWebString key1,
    const int value1, const ArkWebString key2, const int value2, const ArkWebString key3, const int value3)
{
    std::string s_eventName = ArkWebStringStructToClass(eventName);
    std::string s_key1 = ArkWebStringStructToClass(key1);
    std::string s_key2 = ArkWebStringStructToClass(key2);
    std::string s_key3 = ArkWebStringStructToClass(key3);
    std::tuple data = std::make_tuple(s_key1, value1, s_key2, value2, s_key3, value3);

    return real_.Write(s_eventName, (OHOS::NWeb::HiSysEventAdapter::EventType)type, data);
}

int ArkHiSysEventAdapterImpl::Write(const ArkWebString& eventName, uint32_t type, const ArkWebString key1,
    const int value1, const ArkWebString key2, const ArkWebString value2, const ArkWebString key3, const int value3,
    const ArkWebString key4, const ArkWebString value4)
{
    std::string s_eventName = ArkWebStringStructToClass(eventName);
    std::string s_key1 = ArkWebStringStructToClass(key1);
    std::string s_key2 = ArkWebStringStructToClass(key2);
    std::string s_value2 = ArkWebStringStructToClass(value2);
    std::string s_key3 = ArkWebStringStructToClass(key3);
    std::string s_key4 = ArkWebStringStructToClass(key4);
    std::string s_value4 = ArkWebStringStructToClass(value4);
    std::tuple data = std::make_tuple(s_key1, value1, s_key2, s_value2, s_key3, value3, s_key4, s_value4);
    return real_.Write(s_eventName, (OHOS::NWeb::HiSysEventAdapter::EventType)type, data);
}

int ArkHiSysEventAdapterImpl::Write(const ArkWebString& eventName, uint32_t type, const ArkWebString key1,
    const int64_t value1, const ArkWebString key2, const int value2, const ArkWebString key3,
    const ArkWebUint16Vector value3, const ArkWebString key4, const int value4)
{
    std::string s_eventName = ArkWebStringStructToClass(eventName);
    std::string s_key1 = ArkWebStringStructToClass(key1);
    std::string s_key2 = ArkWebStringStructToClass(key2);
    std::string s_key3 = ArkWebStringStructToClass(key3);
    std::string s_key4 = ArkWebStringStructToClass(key4);
    std::vector<uint16_t> v_value3 = ArkWebBasicVectorStructToClass<uint16_t, ArkWebUint16Vector>(value3);
    std::tuple data = std::make_tuple(s_key1, value1, s_key2, value2, s_key3, v_value3, s_key4, value4);
    return real_.Write(s_eventName, (OHOS::NWeb::HiSysEventAdapter::EventType)type, data);
}

} // namespace OHOS::ArkWeb
