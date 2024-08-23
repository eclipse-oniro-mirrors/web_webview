/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "web_storage.h"
#include "web_errors.h"
#include "nweb_helper.h"
#include "nweb_web_storage.h"

namespace OHOS {
namespace NWeb {
int32_t WebStorage::CJdeleteOrigin(const std::string &origin)
{
    int32_t errCode = NWebError::NO_ERROR;
    std::shared_ptr<OHOS::NWeb::NWebWebStorage> web_storage = OHOS::NWeb::NWebHelper::Instance().GetWebStorage();
    if (web_storage) {
        if (web_storage->DeleteOrigin(origin) == NWebError::INVALID_ORIGIN) {
            errCode = NWebError::INVALID_ORIGIN;
        }
    } else {
        errCode = NWebError::NWEB_ERROR;
    }
    return errCode;
}

void WebStorage::CJdeleteAllData(bool incognito)
{
    std::shared_ptr<OHOS::NWeb::NWebWebStorage> web_storage = OHOS::NWeb::NWebHelper::Instance().GetWebStorage();
    if (web_storage) {
        web_storage->DeleteAllData(incognito);
    }
}
}
}