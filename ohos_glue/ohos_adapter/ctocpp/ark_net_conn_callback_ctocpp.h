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

#ifndef ARK_NET_CONN_CALLBACK_CTOCPP_H_
#define ARK_NET_CONN_CALLBACK_CTOCPP_H_
#pragma once

#include "ohos_adapter/capi/ark_net_connect_adapter_capi.h"
#include "ohos_adapter/include/ark_net_connect_adapter.h"

#include "base/ctocpp/ark_web_ctocpp_ref_counted.h"

namespace OHOS::ArkWeb {

// Wrap a C structure with a C++ class.
// This class may be instantiated and accessed wrapper-side only.
class ArkNetConnCallbackCToCpp
    : public ArkWebCToCppRefCounted<ArkNetConnCallbackCToCpp, ArkNetConnCallback, ark_net_conn_callback_t> {
public:
    ArkNetConnCallbackCToCpp();
    virtual ~ArkNetConnCallbackCToCpp();

    // ArkNetConnCallback methods.
    int32_t NetAvailable() override;

    int32_t NetCapabilitiesChange(const uint32_t& netConnectType, const uint32_t& netConnectSubtype) override;

    int32_t NetConnectionPropertiesChange() override;

    int32_t NetUnavailable() override;
};

} // namespace OHOS::ArkWeb

#endif // ARK_NET_CONN_CALLBACK_CTOCPP_H_
