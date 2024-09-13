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

#ifndef ARK_OHOS_NATIVE_BUFFER_ADAPTER_H
#define ARK_OHOS_NATIVE_BUFFER_ADAPTER_H
#pragma once

#include "base/include/ark_web_base_ref_counted.h"
#include "base/include/ark_web_types.h"

namespace OHOS::ArkWeb {

/*--ark web(source=webview)--*/
class ArkOhosNativeBufferAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--ark web()--*/
    ArkOhosNativeBufferAdapter() = default;

    /*--ark web()--*/
    virtual ~ArkOhosNativeBufferAdapter() = default;

    /*--ark web()--*/
    virtual void AcquireBuffer(void* buffer) = 0;

    /*--ark web()--*/
    virtual void Allocate(const void* desc, void** outBuffer) = 0;

    /*--ark web()--*/
    virtual void Describe(const void* buffer, void* outDesc) = 0;

    /*--ark web()--*/
    virtual int Lock(void* buffer,
        uint64_t usage, int32_t fence, const void* rect, void** out_virtual_address) = 0;

    /*--ark web()--*/
    virtual void Release(void* buffer) = 0;

    /*--ark web()--*/
    virtual int RecvHandleFromUnixSocket(int socketFd, void** outBuffer) = 0;

    /*--ark web()--*/
    virtual int SendHandleToUnixSocket(const void* buffer, int socketFd) = 0;

    /*--ark web()--*/
    virtual int Unlock(void* buffer, int32_t* fence) = 0;

    /*--ark web()--*/
    virtual int GetEGLBuffer(void* buffer, void** eglBuffer) = 0;

    /*--ark web()--*/
    virtual int FreeEGLBuffer(void* eglBuffer) = 0;

    /*--ark web()--*/
    virtual int NativeBufferFromNativeWindowBuffer(void* nativeWindowBuffer, void** nativeBuffer) = 0;

    /*--ark web()--*/
    virtual int FreeNativeBuffer(void* nativeBuffer) = 0;
};

} // namespace OHOS::ArkWeb

#endif // ARK_OHOS_NATIVE_BUFFER_ADAPTER_H
