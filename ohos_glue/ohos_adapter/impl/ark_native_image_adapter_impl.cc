/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "ark_native_image_adapter_impl.h"

namespace OHOS::ArkWeb {

ArkNativeImageAdapterImpl::ArkNativeImageAdapterImpl(std::shared_ptr<OHOS::NWeb::NativeImageAdapter> ref) : real_(ref)
{}

void ArkNativeImageAdapterImpl::CreateNativeImage(uint32_t textureId, uint32_t textureTarget)
{
    return real_->CreateNativeImage(textureId, textureTarget);
}
void* ArkNativeImageAdapterImpl::AquireNativeWindowFromNativeImage()
{
    return real_->AquireNativeWindowFromNativeImage();
}
int32_t ArkNativeImageAdapterImpl::AttachContext(uint32_t textureId)
{
    return real_->AttachContext(textureId);
}
int32_t ArkNativeImageAdapterImpl::DetachContext()
{
    return real_->DetachContext();
}

int32_t ArkNativeImageAdapterImpl::UpdateSurfaceImage()
{
    return real_->UpdateSurfaceImage();
}

int64_t ArkNativeImageAdapterImpl::GetTimestamp()
{
    return real_->GetTimestamp();
}

int32_t ArkNativeImageAdapterImpl::GetTransformMatrix(float matrix[16])
{
    return real_->GetTransformMatrix(matrix);
}

int32_t ArkNativeImageAdapterImpl::GetSurfaceId(uint64_t* surfaceId)
{
    return real_->GetSurfaceId(surfaceId);
}

int32_t ArkNativeImageAdapterImpl::SetOnFrameAvailableListener(ArkOnFrameAvailableListener* listener)
{
    return real_->SetOnFrameAvailableListener(reinterpret_cast<OHOS::NWeb::OnFrameAvailableListener*>(listener));
}

int32_t ArkNativeImageAdapterImpl::UnsetOnFrameAvailableListener()
{
    return real_->UnsetOnFrameAvailableListener();
}

void ArkNativeImageAdapterImpl::DestroyNativeImage()
{
    return real_->DestroyNativeImage();
}

} // namespace OHOS::ArkWeb