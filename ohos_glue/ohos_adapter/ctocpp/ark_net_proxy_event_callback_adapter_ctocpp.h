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

#ifndef ARK_NET_PROXY_EVENT_CALLBACK_ADAPTER_CTOCPP_H
#define ARK_NET_PROXY_EVENT_CALLBACK_ADAPTER_CTOCPP_H
#pragma once

#include "capi/ark_net_proxy_adapter_capi.h"
#include "ctocpp/ark_web_ctocpp_ref_counted.h"
#include "include/ark_net_proxy_adapter.h"

namespace OHOS::ArkWeb {

// Wrap a C structure with a C++ class.
// This class may be instantiated and accessed wrapper-side only.
class ArkNetProxyEventCallbackAdapterCToCpp
    : public ArkWebCToCppRefCounted<ArkNetProxyEventCallbackAdapterCToCpp, ArkNetProxyEventCallbackAdapter,
          ark_net_proxy_event_callback_adapter_t> {
public:
    ArkNetProxyEventCallbackAdapterCToCpp();
    virtual ~ArkNetProxyEventCallbackAdapterCToCpp();

    // ArkNetProxyEventCallbackAdapter methods.
    void Changed(const ArkWebString& host, const uint16_t& port, const ArkWebString& pacUrl,
        const ArkWebStringVector& exclusionList) override;
};

} // namespace OHOS::ArkWeb

#endif // ARK_NET_PROXY_EVENT_CALLBACK_ADAPTER_CTOCPP_H