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

#include "ohos_native_buffer_adapter_impl.h"
#include "nweb_log.h"

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES3/gl3.h>

namespace OHOS::NWeb {

OhosNativeBufferAdapter& OhosNativeBufferAdapterImpl::GetInstance()
{
    WVLOG_D("Native buffer adapter impl get instance.");
    static OhosNativeBufferAdapterImpl instance;
    return instance;
}

OhosNativeBufferAdapterImpl::OhosNativeBufferAdapterImpl()
{
    WVLOG_D("Native buffer adapter impl constructor.");
}

OhosNativeBufferAdapterImpl::~OhosNativeBufferAdapterImpl()
{
    WVLOG_D("Native buffer adapter impl destructor.");
}

bool OhosNativeBufferAdapterImpl::IsBufferLocked(OH_NativeBuffer* buffer) const
{
    auto it = lockedBuffers_.find(buffer);
    bool result = (it != lockedBuffers_.end() && it->second);
    WVLOG_D("Native buffer is locked: %{public}s", result ? "yes" : "no");
    return result;
}

void OhosNativeBufferAdapterImpl::Allocate(const NativeBufferDesc* desc, NativeBuffer** outBuffer)
{
    if (desc == nullptr) return;
    WVLOG_D("native buffer allocate, %{public}d * %{public}d, format: %{public}d",
            desc->width, desc->height, desc->format);
    
    OH_NativeBuffer_Config config = {
        .width = desc->width,
        .height = desc->height,
        .format = OH_NativeBuffer_Format::NATIVEBUFFER_PIXEL_FMT_RGBA_8888,
        .usage = desc->usage,
    };

    NativeBufferDesc* storedDesc = new NativeBufferDesc();
    storedDesc->width = desc->width;
    storedDesc->height = desc->height;
    storedDesc->format = OH_NativeBuffer_Format::NATIVEBUFFER_PIXEL_FMT_RGBA_8888;
    storedDesc->usage = desc->usage;

    // create a new OH_NativeBuffer using the OHOS native buffer allocation function
    // The plan here is that the actual buffer holder will be held onto by chromium.

    OH_NativeBuffer* buffer = OH_NativeBuffer_Alloc(&config);
    if (buffer != nullptr) {
        WVLOG_D("native buffer allocate success, rawbuffer stored %{public}p", buffer);
        *outBuffer = new NativeBuffer;
        (*outBuffer)->rawbuffer = buffer;
        configDescriptors_[static_cast<OH_NativeBuffer*>((*outBuffer)->rawbuffer)] = storedDesc;
    } else {
        WVLOG_E("native buffer allocate failed.");
        *outBuffer = nullptr;
    }
}

void OhosNativeBufferAdapterImpl::AcquireBuffer(NativeBuffer* buffer)
{
    if (buffer == nullptr || buffer->rawbuffer == nullptr) {
        WVLOG_E("native buffer acquire, buffer or rawbuffer is null.");
        return;
    }
    WVLOG_D("native buffer acquired buffer %{public}p.", buffer->rawbuffer);
    OH_NativeBuffer_Reference(static_cast<OH_NativeBuffer*>(buffer->rawbuffer));
}

void OhosNativeBufferAdapterImpl::Describe(const NativeBuffer* buffer, NativeBufferDesc* outDesc)
{
    if (buffer == nullptr || outDesc == nullptr || buffer->rawbuffer == nullptr) {
        WVLOG_E("native buffer describe, buffer or rawbuffer or outDesc is null.");
        return;
    }
    WVLOG_D("native buffer describe buffer %{public}p.", buffer->rawbuffer);

    auto it = configDescriptors_.find(static_cast<OH_NativeBuffer*>(buffer->rawbuffer));
    if (it != configDescriptors_.end()) {
        *outDesc = *it->second;
    } else {
        WVLOG_E("native buffer describe cannot find.");
        outDesc->width = 0;
        outDesc->height = 0;
        outDesc->format = 0;
        outDesc->usage = 0;
    }
}

int OhosNativeBufferAdapterImpl::Lock(NativeBuffer* buffer, uint64_t usage, int32_t fence,
    const ARect* rect, void** out_virtual_address)
{
    WVLOG_D("native buffer waiting for lock.");
    if (buffer == nullptr || buffer->rawbuffer == nullptr) {
        WVLOG_E("native buffer lock, buffer or rawbuffer is null.");
        return -1;
    }

    if (IsBufferLocked(static_cast<OH_NativeBuffer*>(buffer->rawbuffer))) {
        WVLOG_D("native buffer lock - buffer already locked.");
        return -1;
    }

    lockedBuffers_[static_cast<OH_NativeBuffer*>(buffer->rawbuffer)] = true;

    return OH_NativeBuffer_Map(static_cast<OH_NativeBuffer*>(buffer->rawbuffer), out_virtual_address);
}
    
int OhosNativeBufferAdapterImpl::RecvHandleFromUnixSocket(int socketFd, NativeBuffer** outBuffer)
{
    WVLOG_D("native buffer receive handle from unix socket.");
    return 0;
}

void OhosNativeBufferAdapterImpl::Release(NativeBuffer* buffer)
{
    if (buffer == nullptr || buffer->rawbuffer == nullptr) {
        WVLOG_E("native buffer release, buffer or rawbuffer is null.");
        return;
    }

    WVLOG_D("native buffer release buffer %{public}p.", buffer->rawbuffer);
    OHOS::SurfaceBuffer *sfBuffer = reinterpret_cast<SurfaceBuffer*>(buffer->rawbuffer);
    int refCount = sfBuffer->GetSptrRefCount();
    if (OH_NativeBuffer_Unreference(static_cast<OH_NativeBuffer*>(buffer->rawbuffer)) == 0) {
        WVLOG_D("native buffer release, unreference buffer.");
    }

    if (refCount == 1) {
        auto it = configDescriptors_.find(static_cast<OH_NativeBuffer*>(buffer->rawbuffer));
        if (it != configDescriptors_.end()) {
            WVLOG_E("native buffer release find in descriptors, for raw buffer: %{public}p.", buffer->rawbuffer);
            delete it->second;
            configDescriptors_.erase(static_cast<OH_NativeBuffer*>(buffer->rawbuffer));
        }
    }

    delete buffer;
}

int OhosNativeBufferAdapterImpl::SendHandleToUnixSocket(const NativeBuffer* buffer, int socketFd)
{
    WVLOG_D("native buffer send handle to unix socket.");

    if (buffer == nullptr || buffer->rawbuffer == nullptr) {
        WVLOG_E("native buffer SendHandleToUnixSocket, buffer or rawbuffer is null.");
        return -1;
    }

    return 0;
}

int OhosNativeBufferAdapterImpl::Unlock(NativeBuffer* buffer, int32_t* fence)
{
    WVLOG_D("native buffer waiting for unlock.");
    if (buffer == nullptr || buffer->rawbuffer == nullptr) {
        WVLOG_E("native buffer lock, buffer or rawbuffer is null.");
        return -1;
    }

    if (!IsBufferLocked(static_cast<OH_NativeBuffer*>(buffer->rawbuffer))) {
        WVLOG_D("native buffer unlock - buffer is already unlocked.");
        return -1;
    }

    int result = OH_NativeBuffer_Unmap(static_cast<OH_NativeBuffer*>(buffer->rawbuffer));
    lockedBuffers_.erase(static_cast<OH_NativeBuffer*>(buffer->rawbuffer));
    configDescriptors_.erase(static_cast<OH_NativeBuffer*>(buffer->rawbuffer));
    return result;
}

int OhosNativeBufferAdapterImpl::GetEGLBuffer(NativeBuffer* buffer, void** eglBuffer)
{
    if (buffer == nullptr || buffer->rawbuffer == nullptr) {
        WVLOG_E("native buffer get egl buffer, buffer or rawbuffer is null.");
        return -1;
    }
    WVLOG_D("native buffer GetEGLBuffer %{public}p.", buffer->rawbuffer);

    OHNativeWindowBuffer* nativeWindowBuffer =
        OH_NativeWindow_CreateNativeWindowBufferFromNativeBuffer(static_cast<OH_NativeBuffer*>(buffer->rawbuffer));
    if (nativeWindowBuffer == nullptr) {
        WVLOG_E("native buffer failed to create native window buffer from native buffer.");
        return -1;
    } else {
        WVLOG_D("native buffer create native window buffer from native bufferL %{public}p.", *eglBuffer);
        *eglBuffer = nativeWindowBuffer;
        return 0;
    }
}

int OhosNativeBufferAdapterImpl::FreeEGLBuffer(void* eglBuffer)
{
    if (eglBuffer == nullptr) {
        WVLOG_E("native buffer free EGLBuffer is null.");
        return -1;
    }

    WVLOG_D("native buffer free EGLBuffer %{public}p", eglBuffer);
    OH_NativeWindow_NativeObjectUnreference(eglBuffer);
    return 0;
}

int OhosNativeBufferAdapterImpl::NativeBufferFromNativeWindowBuffer(void* nativeWindowBuffer, void** nativeBuffer)
{
    if (nativeWindowBuffer == nullptr) {
        WVLOG_E("native buffer NativeBufferFromNativeWindowBuffer, native window buffer is null.");
        return -1;
    }

    *nativeBuffer = OH_NativeBufferFromNativeWindowBuffer(static_cast<NativeWindowBuffer*>(nativeWindowBuffer));
    if (*nativeBuffer == nullptr) {
        WVLOG_E("native buffer NativeBufferFromNativeWindowBuffer, native buffer is null.");
        return -1;
    }
    WVLOG_D("native buffer NativeBufferFromNativeWindowBuffer %{public}p", nativeWindowBuffer);
    return 0;
}

int OhosNativeBufferAdapterImpl::FreeNativeBuffer(void* nativeBuffer)
{
    if (nativeBuffer == nullptr) {
        WVLOG_E("native buffer FreeNativeBuffer, native buffer is null.");
        return -1;
    }
    WVLOG_D("native buffer FreeNativeBuffer freeing: %{public}p.", nativeBuffer);
    OH_NativeBuffer_Unreference(static_cast<OH_NativeBuffer*>(nativeBuffer));
    return 0;
}
} // namespace OHOS::NWeb
