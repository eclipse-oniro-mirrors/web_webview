/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "web_native_messaging_extension_stub.h"

#include <sys/types.h>
#include <unistd.h>
#include "ipc_skeleton.h"
#include "ipc_types.h"
#include "web_native_messaging_log.h"

namespace OHOS {
namespace NWeb {
namespace {
// web_native_messaging SA 服务进程的固定 UID，由 init 依据 /system/etc/passwd 中
// web_native_messaging_service 用户行（uid/gid 3351）设置，与本仓 web_native_messaging_service.cfg
// 中 "uid": "web_native_messaging_service" 用户名配置对应
constexpr int32_t WEB_NATIVE_MESSAGING_UID = 3351;
} // namespace

int32_t WebNativeMessagingExtensionStub::OnRemoteRequest(uint32_t code, MessageParcel& data,
    MessageParcel& reply, MessageOption& option)
{
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }

    // 仅允许 web_native_messaging SA 服务进程调用，防止其他进程绕过 SA 服务层权限校验直接访问扩展
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid != WEB_NATIVE_MESSAGING_UID) {
        WNMLOG_E("OnRemoteRequest denied caller, callingUid = %{public}d", callingUid);
        return ERR_INVALID_VALUE;
    }

    switch (code) {
        case IWebNativeMessagingExtension::CODE_CONNECTNATIVE: {
            WNMEConnectionInfo connInfo;
            if (!WNMEConnectionInfoParcel::Unmarshalling(data, connInfo)) {
                WNMLOG_E("ConnectNative unmarshalling connInfo failed");
                reply.WriteInt32(WNME_PARAMS_INVALID);
                return ERR_NONE;
            }
            int32_t errorCode = ConnectNative(connInfo);
            if (errorCode == WNME_SUCCESS) {
                errorCode = getpid();
            }
            reply.WriteInt32(errorCode);
            return ERR_NONE;
        }

        case IWebNativeMessagingExtension::CODE_DISCONNECTNATIVE: {
            WNMEConnectionInfo connInfo;
            if (!WNMEConnectionInfoParcel::Unmarshalling(data, connInfo)) {
                WNMLOG_E("DisconnectNative unmarshalling connInfo failed");
                reply.WriteInt32(WNME_PARAMS_INVALID);
                return ERR_NONE;
            }
            int32_t errorCode = DisconnectNative(connInfo);
            reply.WriteInt32(errorCode);
            return ERR_NONE;
        }

        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }

    return ERR_TRANSACTION_FAILED;
}
} // namespace NWeb
} // namespace OHOS
