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

#ifndef ARK_WEB_WEB_STORAGE_ORIGIN_IMPL_H_
#define ARK_WEB_WEB_STORAGE_ORIGIN_IMPL_H_
#pragma once

#include "include/nweb_web_storage.h"
#include "ohos_nweb/include/ark_web_web_storage_origin.h"

namespace OHOS::ArkWeb {

class ArkWebWebStorageOriginImpl : public ArkWebWebStorageOrigin {
    IMPLEMENT_REFCOUNTING(ArkWebWebStorageOrigin);

public:
    ArkWebWebStorageOriginImpl(std::shared_ptr<OHOS::NWeb::NWebWebStorageOrigin> nweb_web_storage_origin);
    ~ArkWebWebStorageOriginImpl() = default;

    long GetQuota() override;

    void SetQuota(long quota) override;

    long GetUsage() override;

    void SetUsage(long usage) override;

    ArkWebString GetOrigin() override;

    void SetOrigin(const ArkWebString& origin) override;

private:
    std::shared_ptr<OHOS::NWeb::NWebWebStorageOrigin> nweb_web_storage_origin_;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_WEB_STORAGE_ORIGIN_IMPL_H_
