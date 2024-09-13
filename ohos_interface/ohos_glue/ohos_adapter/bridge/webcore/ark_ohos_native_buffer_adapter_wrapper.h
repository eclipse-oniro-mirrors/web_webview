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

#ifndef ARK_OHOS_NATIVE_BUFFER_ADAPTER_WRAPPER_H
#define ARK_OHOS_NATIVE_BUFFER_ADAPTER_WRAPPER_H
#pragma once

#include "ohos_adapter/include/ark_ohos_native_buffer_adapter.h"
#include "ohos_native_buffer_adapter.h"

namespace OHOS::ArkWeb {
using namespace OHOS::NWeb;

class ArkOhosNativeBufferAdapterWrapper : public OHOS::NWeb::OhosNativeBufferAdapter {
public:
    ArkOhosNativeBufferAdapterWrapper(ArkWebRefPtr<ArkOhosNativeBufferAdapter>);

    void Allocate(const NativeBufferDesc* desc, NativeBuffer** outBuffer) override;
    void AcquireBuffer(NativeBuffer* buffer) override;
    void Describe(const NativeBuffer* buffer, NativeBufferDesc* outDesc) override;
    int Lock(NativeBuffer* buffer,
        uint64_t usage, int32_t fence, const ARect* rect, void** out_virtual_address) override;
    int RecvHandleFromUnixSocket(int socketFd, NativeBuffer** outBuffer) override;
    void Release(NativeBuffer* buffer) override;
    int SendHandleToUnixSocket(const NativeBuffer* buffer, int socketFd) override;
    int Unlock(NativeBuffer* buffer, int32_t* fence) override;
    int GetEGLBuffer(NativeBuffer* buffer, void** eglBuffer) override;
    int FreeEGLBuffer(void* eglBuffer) override;
    int NativeBufferFromNativeWindowBuffer(void* nativeWindowBuffer, void** nativeBuffer) override;
    int FreeNativeBuffer(void* nativeBuffer) override;

private:
    ArkWebRefPtr<ArkOhosNativeBufferAdapter> ctocpp_;
};

} // namespace OHOS::ArkWeb

#endif // ARK_OHOS_NATIVE_BUFFER_ADAPTER_WRAPPER_H
