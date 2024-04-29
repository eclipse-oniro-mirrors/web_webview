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

#ifndef ARK_SOC_PERF_CLIENT_ADAPTER_H
#define ARK_SOC_PERF_CLIENT_ADAPTER_H
#pragma once

#include "base/include/ark_web_base_ref_counted.h"

namespace OHOS::ArkWeb {

/*--ark web(source=library)--*/
class ArkSocPerfClientAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--ark web()--*/
    virtual void ApplySocPerfConfigById(int32_t id) = 0;

    /*--ark web()--*/
    virtual void ApplySocPerfConfigByIdEx(int32_t id, bool onOffTag) = 0;
};

} // namespace OHOS::ArkWeb

#endif // ARK_SOC_PERF_CLIENT_ADAPTER_H
