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

#ifndef ARK_HISYSEVENT_ADAPTER_CAPI_H
#define ARK_HISYSEVENT_ADAPTER_CAPI_H
#pragma once

#include "capi/ark_web_base_ref_counted_capi.h"
#include "include/ark_web_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _ark_hi_sys_event_adapter_t {
    /**
     * @brief Base structure.
     */
    ark_web_base_ref_counted_t base;

    int(ARK_WEB_CALLBACK* write1)(struct _ark_hi_sys_event_adapter_t* self, const ArkWebString* eventName,
        uint32_t type, const ArkWebString key1, const int value1, const ArkWebString key2, const int value2,
        const ArkWebString key3, const int value3, const ArkWebString key4, const int value4, const ArkWebString key5,
        const float value5);

    int(ARK_WEB_CALLBACK* write2)(struct _ark_hi_sys_event_adapter_t* self, const ArkWebString* eventName,
        uint32_t type, const ArkWebString key1, const int value1, const ArkWebString key2, const int value2,
        const ArkWebString key3, const int value3);

    int(ARK_WEB_CALLBACK* write3)(struct _ark_hi_sys_event_adapter_t* self, const ArkWebString* eventName,
        uint32_t type, const ArkWebString key1, const int value1, const ArkWebString key2, const ArkWebString value2,
        const ArkWebString key3, const int value3, const ArkWebString key4, const ArkWebString value4);

    int(ARK_WEB_CALLBACK* write4)(struct _ark_hi_sys_event_adapter_t* self, const ArkWebString* eventName,
        uint32_t type, const ArkWebString key1, const int64_t value1, const ArkWebString key2, const int value2,
        const ArkWebString key3, const ArkWebUint16Vector value3, const ArkWebString key4, const int value4);
} ark_hi_sys_event_adapter_t;

#ifdef __cplusplus
}
#endif

#endif // ARK_HISYSEVENT_ADAPTER_CAPI_H