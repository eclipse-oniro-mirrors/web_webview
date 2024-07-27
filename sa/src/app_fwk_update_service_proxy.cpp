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

#include "app_fwk_update_service_proxy.h"

namespace OHOS {
namespace NWeb {
ErrCode AppFwkUpdateServiceProxy::RequestUpdateService(
    const std::string& bundleName)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        return ERR_INVALID_VALUE;
    }

    if (!data.WriteString16(Str8ToStr16(bundleName))) {
        return ERR_INVALID_DATA;
    }

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return ERR_INVALID_DATA;
    }
    int32_t result = remote->SendRequest(COMMAND_REQUEST_UPDATE_SERVICE, data, reply, option);
    if (FAILED(result)) {
        return result;
    }

    ErrCode errCode = reply.ReadInt32();
    if (FAILED(errCode)) {
        return errCode;
    }

    return ERR_OK;
}
} // namespace NWeb
} // namespace OHOS
