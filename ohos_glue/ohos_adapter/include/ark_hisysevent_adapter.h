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

#ifndef ARK_HISYSEVENT_ADAPTER_H
#define ARK_HISYSEVENT_ADAPTER_H

#pragma once

#include "include/ark_web_base_ref_counted.h"
#include "include/ark_web_types.h"

namespace OHOS::ArkWeb {

/*--web engine(source=library)--*/
class ArkHiSysEventAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    virtual int Write(const ArkWebString &eventName, uint32_t type,
        const ArkWebString key1, const ArkWebString value1) = 0;

    /*--web engine()--*/
    virtual int Write(const ArkWebString &eventName, uint32_t type,
        const ArkWebString key1, const ArkWebString value1,
        const ArkWebString key2, const ArkWebString value2) = 0;

    /*--web engine()--*/
    virtual int Write(const ArkWebString &eventName, uint32_t type,
        const ArkWebString key1, const ArkWebString value1,
        const ArkWebString key2, const ArkWebString value2,
        const ArkWebString key3, const ArkWebString value3) = 0;

    /*--web engine()--*/
    virtual int Write(const ArkWebString &eventName, uint32_t type,
        const ArkWebString key1, const ArkWebString value1,
        const ArkWebString key2, const ArkWebString value2,
        const ArkWebString key3, const ArkWebString value3,
        const ArkWebString key4, const ArkWebString value4) = 0;

    /*--web engine()--*/
    virtual int Write(const ArkWebString &eventName, uint32_t type,
        const ArkWebString key1, const ArkWebString value1,
        const ArkWebString key2, const ArkWebString value2,
        const ArkWebString key3, const ArkWebString value3,
        const ArkWebString key4, const ArkWebString value4,
        const ArkWebString key5, const ArkWebString value5) = 0;

    /*--web engine()--*/
    virtual int Write(const ArkWebString &eventName, uint32_t type,
        const ArkWebString key1, const ArkWebString value1,
        const ArkWebString key2, const ArkWebString value2,
        const ArkWebString key3, const ArkWebString value3,
        const ArkWebString key4, const ArkWebString value4,
        const ArkWebString key5, const ArkWebString value5,
        const ArkWebString key6, const ArkWebString value6) = 0;

    /*--web engine()--*/
    virtual int Write(const ArkWebString &eventName, uint32_t type, const ArkWebString key1, const int64_t value1,
        const ArkWebString key2, const int value2, const ArkWebString key3, const ArkWebUint16Vector value3,
        const ArkWebString key4, const int value4) = 0;
};
} // namespace OHOS::ArkWeb

#endif // ARK_HISYSEVENT_ADAPTER_H
