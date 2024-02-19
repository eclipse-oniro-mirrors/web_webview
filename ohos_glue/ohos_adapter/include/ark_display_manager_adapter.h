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

#ifndef ARK_DISPLAY_MANAGER_ADAPTER_H
#define ARK_DISPLAY_MANAGER_ADAPTER_H

#include "include/ark_web_base_ref_counted.h"
#include "include/ark_web_types.h"

namespace OHOS::ArkWeb {

/*--web engine(source=client)--*/
class ArkDisplayListenerAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkDisplayListenerAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkDisplayListenerAdapter() = default;

    /*--web engine()--*/
    virtual void OnCreate(uint64_t displayId) = 0;

    /*--web engine()--*/
    virtual void OnDestroy(uint64_t displayId) = 0;

    /*--web engine()--*/
    virtual void OnChange(uint64_t displayId) = 0;
};

/*--web engine(source=library)--*/
class ArkDisplayAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkDisplayAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkDisplayAdapter() = default;

    /*--web engine()--*/
    virtual uint64_t GetId() = 0;

    /*--web engine()--*/
    virtual int32_t GetWidth() = 0;

    /*--web engine()--*/
    virtual int32_t GetHeight() = 0;

    /*--web engine()--*/
    virtual float GetVirtualPixelRatio() = 0;

    /*--web engine()--*/
    virtual uint32_t GetRotation() = 0;

    /*--web engine()--*/
    virtual uint32_t GetOrientation() = 0;
};

/*--web engine(source=library)--*/
class ArkDisplayManagerAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkDisplayManagerAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkDisplayManagerAdapter() = default;

    /*--web engine()--*/
    virtual uint64_t GetDefaultDisplayId() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkDisplayAdapter> GetDefaultDisplay() = 0;

    /*--web engine()--*/
    virtual uint32_t RegisterDisplayListener(ArkWebRefPtr<ArkDisplayListenerAdapter> listener) = 0;

    /*--web engine()--*/
    virtual bool UnregisterDisplayListener(uint32_t id) = 0;

    /*--web engine()--*/
    virtual bool IsDefaultPortrait() = 0;
};
} // namespace OHOS::ArkWeb

#endif // ARK_DISPLAY_MANAGER_ADAPTER_H
