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

#include <atomic>
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>
#include "ipc_skeleton.h"
#include "ipc_types.h"
#include "web_native_messaging_log.h"

namespace OHOS {
namespace NWeb {
namespace {
// web_native_messaging SA 服务进程用户名，与本仓 web_native_messaging_service.cfg 中
// "uid": "web_native_messaging_service" 配置对应；uid 由 init 依据 /system/etc/passwd 分配，
// 运行时动态解析以避免硬编码 uid 带来的可移植性风险
constexpr char WEB_NATIVE_MESSAGING_USER[] = "web_native_messaging_service";

// 查询 web_native_messaging SA 服务进程 uid，首次成功后缓存（/system 分区只读，passwd 运行期不变）
// 查询失败返回 -1，由调用方按拒绝处理（fail-closed）
int32_t GetWebNativeMessagingUid()
{
    static std::atomic<int32_t> cachedUid { -1 };
    int32_t uid = cachedUid.load(std::memory_order_acquire);
    if (uid >= 0) {
        return uid;
    }
    struct passwd entry = {};
    struct passwd* result = nullptr;
    char buf[1024];
    if (getpwnam_r(WEB_NATIVE_MESSAGING_USER, &entry, buf, sizeof(buf), &result) != 0 || result == nullptr) {
        WNMLOG_E("fail to get uid of %{public}s", WEB_NATIVE_MESSAGING_USER);
        return -1;
    }
    uid = static_cast<int32_t>(result->pw_uid);
    cachedUid.store(uid, std::memory_order_release);
    return uid;
}
} // namespace

int32_t WebNativeMessagingExtensionStub::OnRemoteRequest(uint32_t code, MessageParcel& data,
    MessageParcel& reply, MessageOption& option)
{
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }

    // 仅允许 web_native_messaging SA 服务进程调用，防止其他进程绕过 SA 服务层权限校验直接访问扩展
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid != GetWebNativeMessagingUid()) {
        WNMLOG_E("OnRemoteRequest denied caller, callingUid = %{public}d", callingUid);
        reply.WriteInt32(WNME_INNER_ERROR);
        return ERR_NONE;
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
