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

#ifndef ARK_ACCESS_TOKEN_ADAPTER_H
#define ARK_ACCESS_TOKEN_ADAPTER_H

#include "include/ark_web_base_ref_counted.h"
#include "include/ark_web_types.h"

namespace OHOS::ArkWeb {

/*--web engine(source=library)--*/
class ArkAccessTokenAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    virtual bool VerifyAccessToken(const ArkWebString& permissionName) = 0;

protected:
    /*--web engine()--*/
    ArkAccessTokenAdapter() = default;
    /*--web engine()--*/
    virtual ~ArkAccessTokenAdapter() = default;
};
} // namespace OHOS::ArkWeb

#endif // ARK_ACCESS_TOKEN_ADAPTER_H