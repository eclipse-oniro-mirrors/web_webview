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

#ifndef ARK_POWER_MGR_CLIENT_ADAPTER_H
#define ARK_POWER_MGR_CLIENT_ADAPTER_H

#pragma once

#include <cstdint>

#include "include/ark_web_base_ref_counted.h"
#include "include/ark_web_types.h"

namespace OHOS::ArkWeb {

/*--web engine(source=library)--*/
class ArkRunningLockAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkRunningLockAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkRunningLockAdapter() = default;

    /*--web engine()--*/
    virtual bool IsUsed() = 0;

    /*--web engine()--*/
    virtual int32_t Lock(uint32_t timeOutMs) = 0;

    /*--web engine()--*/
    virtual int32_t UnLock() = 0;
};

/*--web engine(source=library)--*/
class ArkPowerMgrClientAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkPowerMgrClientAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkPowerMgrClientAdapter() = default;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkRunningLockAdapter> CreateRunningLock(const ArkWebString& name, uint32_t type) = 0;
};
} // namespace OHOS::ArkWeb

#endif // ARK_POWER_MGR_CLIENT_ADAPTER_H
