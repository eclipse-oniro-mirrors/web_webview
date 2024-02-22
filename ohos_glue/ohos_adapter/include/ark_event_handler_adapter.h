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

#ifndef ARK_EVENT_HANDLER_ADAPTER_H
#define ARK_EVENT_HANDLER_ADAPTER_H

#pragma once

#include "include/ark_web_base_ref_counted.h"
#include "include/ark_web_types.h"

namespace OHOS::ArkWeb {

/*--web engine(source=client)--*/
class ArkEventHandlerFDListenerAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkEventHandlerFDListenerAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkEventHandlerFDListenerAdapter() = default;

    /*--web engine()--*/
    virtual void OnReadable(int32_t fileDescriptor) = 0;
};

/*--web engine(source=library)--*/
class ArkEventHandlerAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkEventHandlerAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkEventHandlerAdapter() = default;

    /*--web engine()--*/
    virtual bool AddFileDescriptorListener(
        int32_t fileDescriptor, uint32_t events, const ArkWebRefPtr<ArkEventHandlerFDListenerAdapter> listener) = 0;

    /*--web engine()--*/
    virtual void RemoveFileDescriptorListener(int32_t fileDescriptor) = 0;
};
} // namespace OHOS::ArkWeb

#endif // ARK_EVENT_HANDLER_ADAPTER_H
