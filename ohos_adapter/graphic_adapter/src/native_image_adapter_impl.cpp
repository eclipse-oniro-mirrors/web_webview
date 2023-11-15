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

#include "native_image_adapter_impl.h"
#include "iconsumer_surface.h"

namespace OHOS::NWeb {

constexpr int NATIVE_IMAGE_ADAPTER_FATAL_ERROR = 50002000;

NativeImageAdapterImpl::~NativeImageAdapterImpl()
{
    DestroyNativeImage();
}

void NativeImageAdapterImpl::CreateNativeImage(uint32_t textureId, uint32_t textureTarget)
{
    ohNativeImage_ = OH_NativeImage_Create(textureId, textureTarget);
}

NWebNativeWindow NativeImageAdapterImpl::AquireNativeWindowFromNativeImage()
{
    if (ohNativeImage_ == nullptr) {
        return nullptr;
    }
    return reinterpret_cast<NWebNativeWindow>(OH_NativeImage_AcquireNativeWindow(ohNativeImage_));
}

int32_t NativeImageAdapterImpl::AttachContext(uint32_t textureId)
{
    if (ohNativeImage_ == nullptr) {
        return NATIVE_IMAGE_ADAPTER_FATAL_ERROR;
    }
    return OH_NativeImage_AttachContext(ohNativeImage_, textureId);
}

int32_t NativeImageAdapterImpl::DetachContext()
{
    if (ohNativeImage_ == nullptr) {
        return NATIVE_IMAGE_ADAPTER_FATAL_ERROR;
    }
    return OH_NativeImage_DetachContext(ohNativeImage_);
}

int32_t NativeImageAdapterImpl::UpdateSurfaceImage()
{
    if (ohNativeImage_ == nullptr) {
        return NATIVE_IMAGE_ADAPTER_FATAL_ERROR;
    }
    return OH_NativeImage_UpdateSurfaceImage(ohNativeImage_);
}

int64_t NativeImageAdapterImpl::GetTimestamp()
{
    if (ohNativeImage_ == nullptr) {
        return NATIVE_IMAGE_ADAPTER_FATAL_ERROR;
    }
    return OH_NativeImage_GetTimestamp(ohNativeImage_);
}

int32_t NativeImageAdapterImpl::GetTransformMatrix(float matrix[16])
{
    if (ohNativeImage_ == nullptr) {
        return NATIVE_IMAGE_ADAPTER_FATAL_ERROR;
    }
    return OH_NativeImage_GetTransformMatrix(ohNativeImage_, matrix);
}

int32_t NativeImageAdapterImpl::GetSurfaceId(uint64_t* surfaceId)
{
    if (ohNativeImage_ == nullptr) {
        return NATIVE_IMAGE_ADAPTER_FATAL_ERROR;
    }
    OH_NativeImage_GetSurfaceId(ohNativeImage_, surfaceId);
    return 0;
}

int32_t NativeImageAdapterImpl::SetOnFrameAvailableListener(OnFrameAvailableListener* listener)
{
    if (ohNativeImage_ == nullptr || listener == nullptr) {
        return NATIVE_IMAGE_ADAPTER_FATAL_ERROR;
    }
    OH_OnFrameAvailableListener callback;
    callback.onFrameAvailable = listener->cb;
    callback.context = listener->context;
    OH_NativeImage_SetOnFrameAvailableListener(ohNativeImage_, callback);
    return 0;
}

int32_t NativeImageAdapterImpl::UnsetOnFrameAvailableListener()
{
    if (ohNativeImage_ == nullptr) {
        return NATIVE_IMAGE_ADAPTER_FATAL_ERROR;
    }
    OH_NativeImage_UnsetOnFrameAvailableListener(ohNativeImage_);
    return 0;
}

void NativeImageAdapterImpl::DestroyNativeImage()
{
    if (ohNativeImage_ == nullptr) {
        return;
    }
    OH_NativeImage_Destroy(&ohNativeImage_);
    ohNativeImage_ = nullptr;
}
}