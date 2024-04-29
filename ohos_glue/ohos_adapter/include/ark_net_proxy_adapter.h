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

#ifndef ARK_NET_PROXY_ADAPTER_H
#define ARK_NET_PROXY_ADAPTER_H
#pragma once

#include "base/include/ark_web_base_ref_counted.h"
#include "base/include/ark_web_types.h"

namespace OHOS::ArkWeb {

/*--ark web(source=web core)--*/
class ArkNetProxyEventCallbackAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--ark web()--*/
    virtual void Changed(const ArkWebString& host, const uint16_t& port, const ArkWebString& pacUrl,
        const ArkWebStringVector& exclusionList) = 0;
};

/*--ark web(source=library)--*/
class ArkNetProxyAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--ark web()--*/
    virtual void RegNetProxyEvent(ArkWebRefPtr<ArkNetProxyEventCallbackAdapter> eventCallback) = 0;

    /*--ark web()--*/
    virtual bool StartListen() = 0;

    /*--ark web()--*/
    virtual void StopListen() = 0;

    /*--ark web()--*/
    virtual void GetProperty(ArkWebString& host, uint16_t& port, ArkWebString& pacUrl, ArkWebString& exclusion) = 0;
};

} // namespace OHOS::ArkWeb

#endif // ARK_NET_PROXY_ADAPTER_H
