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

#include "base/include/ark_web_log_utils.h"
#include "ohos_adapter/bridge/ark_ohos_native_buffer_adapter_wrapper.h"

#define HILOG_TAG "NATIVE_BUFFER_ADAPTER"

namespace OHOS::ArkWeb {

ArkOhosNativeBufferAdapterWrapper::ArkOhosNativeBufferAdapterWrapper(ArkWebRefPtr<ArkOhosNativeBufferAdapter> ref)
    : ctocpp_(ref) {}

void ArkOhosNativeBufferAdapterWrapper::Allocate(const NativeBufferDesc* desc, NativeBuffer** outBuffer)
{
    ctocpp_->Allocate(desc, reinterpret_cast<void**>(outBuffer));
}

void ArkOhosNativeBufferAdapterWrapper::AcquireBuffer(NativeBuffer* buffer)
{
    ctocpp_->AcquireBuffer(buffer);
}

void ArkOhosNativeBufferAdapterWrapper::Describe(const NativeBuffer* buffer, NativeBufferDesc* outDesc)
{
    ctocpp_->Describe(buffer, outDesc);
}

void ArkOhosNativeBufferAdapterWrapper::Release(NativeBuffer* buffer)
{
    ctocpp_->Release(static_cast<void*>(buffer));
}

int ArkOhosNativeBufferAdapterWrapper::GetEGLBuffer(NativeBuffer* buffer, void** eglBuffer)
{
    return ctocpp_->GetEGLBuffer(buffer, eglBuffer);
}

int ArkOhosNativeBufferAdapterWrapper::FreeEGLBuffer(void* eglBuffer)
{
    return ctocpp_->FreeEGLBuffer(eglBuffer);
}

int ArkOhosNativeBufferAdapterWrapper::NativeBufferFromNativeWindowBuffer(void* nativeWindowBuffer, void** nativeBuffer)
{
    return ctocpp_->NativeBufferFromNativeWindowBuffer(nativeWindowBuffer, nativeBuffer);
}

int ArkOhosNativeBufferAdapterWrapper::FreeNativeBuffer(void* nativeBuffer)
{
    return ctocpp_->FreeNativeBuffer(nativeBuffer);
}

uint32_t ArkOhosNativeBufferAdapterWrapper::GetSeqNum(NativeBuffer* nativeBuffer)
{
    return ctocpp_->GetSeqNum(nativeBuffer);
}
} // namespace OHOS::ArkWeb
