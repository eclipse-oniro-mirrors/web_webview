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

#ifndef ARK_DISPLAY_LISTENER_ADAPTER_CTOCPP_H
#define ARK_DISPLAY_LISTENER_ADAPTER_CTOCPP_H
#pragma once

#include "capi/ark_display_manager_adapter_capi.h"
#include "ctocpp/ark_web_ctocpp_ref_counted.h"
#include "include/ark_display_manager_adapter.h"

namespace OHOS::ArkWeb {

// Wrap a C structure with a C++ class.
// This class may be instantiated and accessed wrapper-side only.
class ArkDisplayListenerAdapterCToCpp : public ArkWebCToCppRefCounted<ArkDisplayListenerAdapterCToCpp,
                                            ArkDisplayListenerAdapter, ark_display_listener_adapter_t> {
public:
    ArkDisplayListenerAdapterCToCpp();
    virtual ~ArkDisplayListenerAdapterCToCpp();

    // ArkDisplayListenerAdapter methods.
    void OnCreate(uint64_t displayId) override;

    void OnDestroy(uint64_t displayId) override;

    void OnChange(uint64_t displayId) override;
};

} // namespace OHOS::ArkWeb

#endif // ARK_DISPLAY_LISTENER_ADAPTER_CTOCPP_H