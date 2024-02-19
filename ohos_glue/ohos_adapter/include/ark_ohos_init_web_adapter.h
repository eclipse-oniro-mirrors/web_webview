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

#ifndef ARK_OHOS_INIT_WEB_ADAPTER_H
#define ARK_OHOS_INIT_WEB_ADAPTER_H

#pragma once

#include "include/ark_web_base_ref_counted.h"
#include "include/ark_web_types.h"
#include "ohos_init_web_adapter.h"

using ArkWebRunInitedCallback = OHOS::NWeb::WebRunInitedCallback;

namespace OHOS::ArkWeb {

/*--web engine(source=library)--*/
class ArkOhosInitWebAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkOhosInitWebAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkOhosInitWebAdapter() = default;

    /*--web engine()--*/
    virtual ArkWebRunInitedCallback* GetRunWebInitedCallback() = 0;

    /*--web engine()--*/
    virtual void SetRunWebInitedCallback(ArkWebRunInitedCallback* callback) = 0;
};
} // namespace OHOS::ArkWeb

#endif // OHOS_INIT_WEB_ADAPTER_H
