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

#include "cpptoc/ark_hi_sys_event_adapter_cpptoc.h"

#include "cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

int ARK_WEB_CALLBACK ark_hi_sys_event_adapter_write1(struct _ark_hi_sys_event_adapter_t* self,
    const ArkWebString* eventName, uint32_t type, const ArkWebString key1, const int value1, const ArkWebString key2,
    const int value2, const ArkWebString key3, const int value3, const ArkWebString key4, const int value4,
    const ArkWebString key5, const float value5)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(eventName, 0);

    // Execute
    return ArkHiSysEventAdapterCppToC::Get(self)->Write(
        *eventName, type, key1, value1, key2, value2, key3, value3, key4, value4, key5, value5);
}

int ARK_WEB_CALLBACK ark_hi_sys_event_adapter_write2(struct _ark_hi_sys_event_adapter_t* self,
    const ArkWebString* eventName, uint32_t type, const ArkWebString key1, const int value1, const ArkWebString key2,
    const int value2, const ArkWebString key3, const int value3)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(eventName, 0);

    // Execute
    return ArkHiSysEventAdapterCppToC::Get(self)->Write(*eventName, type, key1, value1, key2, value2, key3, value3);
}

int ARK_WEB_CALLBACK ark_hi_sys_event_adapter_write3(struct _ark_hi_sys_event_adapter_t* self,
    const ArkWebString* eventName, uint32_t type, const ArkWebString key1, const int value1, const ArkWebString key2,
    const ArkWebString value2, const ArkWebString key3, const int value3, const ArkWebString key4,
    const ArkWebString value4)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(eventName, 0);

    // Execute
    return ArkHiSysEventAdapterCppToC::Get(self)->Write(
        *eventName, type, key1, value1, key2, value2, key3, value3, key4, value4);
}

int ARK_WEB_CALLBACK ark_hi_sys_event_adapter_write4(struct _ark_hi_sys_event_adapter_t* self,
    const ArkWebString* eventName, uint32_t type, const ArkWebString key1, const int64_t value1,
    const ArkWebString key2, const int value2, const ArkWebString key3, const ArkWebUint16Vector value3,
    const ArkWebString key4, const int value4)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(eventName, 0);

    // Execute
    return ArkHiSysEventAdapterCppToC::Get(self)->Write(
        *eventName, type, key1, value1, key2, value2, key3, value3, key4, value4);
}

} // namespace

ArkHiSysEventAdapterCppToC::ArkHiSysEventAdapterCppToC()
{
    GetStruct()->write1 = ark_hi_sys_event_adapter_write1;
    GetStruct()->write2 = ark_hi_sys_event_adapter_write2;
    GetStruct()->write3 = ark_hi_sys_event_adapter_write3;
    GetStruct()->write4 = ark_hi_sys_event_adapter_write4;
}

ArkHiSysEventAdapterCppToC::~ArkHiSysEventAdapterCppToC() {}

template<>
ArkWebBridgeType
    ArkWebCppToCRefCounted<ArkHiSysEventAdapterCppToC, ArkHiSysEventAdapter, ark_hi_sys_event_adapter_t>::kBridgeType =
        ARK_HI_SYS_EVENT_ADAPTER;

} // namespace OHOS::ArkWeb