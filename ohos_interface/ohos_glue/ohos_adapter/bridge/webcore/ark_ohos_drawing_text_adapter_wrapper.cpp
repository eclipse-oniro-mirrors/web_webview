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

#include "base/include/ark_web_log_utils.h"
#include "ohos_adapter/bridge/ark_ohos_drawing_text_adapter_wrapper.h"
#include "base/bridge/ark_web_bridge_macros.h"

namespace OHOS::ArkWeb {

ArkOhosDrawingTextFontAdapterWrapper::ArkOhosDrawingTextFontAdapterWrapper(
    ArkWebRefPtr<ArkOhosDrawingTextFontAdapter> ref) : ctocpp_(ref) {}


int ArkOhosDrawingTextFontAdapterWrapper::GetSystemFontFullNamesByType(int32_t systemFontType, void** drawingArray)
{
    return ctocpp_->GetSystemFontFullNamesByType(systemFontType, drawingArray);
}

int ArkOhosDrawingTextFontAdapterWrapper::GetFontDescriptorByFullName(void* drawingString,
    int32_t systemFontType, void** drawingFontDescriptor)
{
    return ctocpp_->GetFontDescriptorByFullName(drawingString, systemFontType, drawingFontDescriptor);
}

int ArkOhosDrawingTextFontAdapterWrapper::GetSystemFontFullNameByIndex(void* drawingArray,
    int32_t indexOfFullName, const void** drawingString)
{
    return ctocpp_->GetSystemFontFullNameByIndex(drawingArray, indexOfFullName, drawingString);
}

void ArkOhosDrawingTextFontAdapterWrapper::DestroySystemFontFullNames(void* drawingArray)
{
    ctocpp_->DestroySystemFontFullNames(drawingArray);
}

void ArkOhosDrawingTextFontAdapterWrapper::DestroyFontDescriptor(void* descriptor)
{
    ctocpp_->DestroyFontDescriptor(descriptor);
}

ArkOhosDrawingTextTypographyAdapterWrapper::ArkOhosDrawingTextTypographyAdapterWrapper(
    ArkWebRefPtr<ArkOhosDrawingTextTypographyAdapter> ref) : ctocpp_(ref) {}


int ArkOhosDrawingTextTypographyAdapterWrapper::GetSystemFontConfigInfo(void* fontConfigInfoErrorCode,
                                                                        void** fontConfigInfo)
{
    return ctocpp_->GetSystemFontConfigInfo(fontConfigInfoErrorCode, fontConfigInfo);
}

int ArkOhosDrawingTextTypographyAdapterWrapper::GetDrawingArraySize(void* drawingArray, int32_t& sizeOfArray)
{
   return ctocpp_->GetDrawingArraySize(drawingArray, sizeOfArray);
}

void ArkOhosDrawingTextTypographyAdapterWrapper::DestroySystemFontConfigInfo(void* fontConfigInfo)
{
    ctocpp_->DestroySystemFontConfigInfo(fontConfigInfo);
}
} //namespace OHOS::ArkWeb