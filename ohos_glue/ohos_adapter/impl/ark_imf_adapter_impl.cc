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

#include "ark_imf_adapter_impl.h"

#include "bridge/ark_web_bridge_macros.h"
#include "wrapper/ark_imftext_listener_adapter_wrapper.h"

namespace OHOS::ArkWeb {

ArkIMFAdapterImpl::ArkIMFAdapterImpl(std::shared_ptr<OHOS::NWeb::IMFAdapter> ref) : real_(ref) {}

bool ArkIMFAdapterImpl::Attach(ArkWebRefPtr<ArkIMFTextListenerAdapter> listener, bool isShowKeyboard)
{
    if (CHECK_REF_PTR_IS_NULL(listener)) {
        return real_->Attach(nullptr, isShowKeyboard);
    }

    return real_->Attach(std::make_shared<ArkIMFTextListenerAdapterWrapper>(listener), isShowKeyboard);
}

bool ArkIMFAdapterImpl::Attach(
    ArkWebRefPtr<ArkIMFTextListenerAdapter> listener, bool isShowKeyboard, const ArkIMFAdapterTextConfig& config)
{
    if (CHECK_REF_PTR_IS_NULL(listener)) {
        return real_->Attach(nullptr, isShowKeyboard, config);
    }

    return real_->Attach(std::make_shared<ArkIMFTextListenerAdapterWrapper>(listener), isShowKeyboard, config);
}

void ArkIMFAdapterImpl::ShowCurrentInput(const int32_t& inputType)
{
    real_->ShowCurrentInput((OHOS::NWeb::IMFAdapterTextInputType)inputType);
}

void ArkIMFAdapterImpl::HideTextInput()
{
    real_->HideTextInput();
}

void ArkIMFAdapterImpl::Close()
{
    real_->Close();
}

void ArkIMFAdapterImpl::OnCursorUpdate(ArkIMFAdapterCursorInfo cursorInfo)
{
    real_->OnCursorUpdate(cursorInfo);
}

void ArkIMFAdapterImpl::OnSelectionChange(ArkWebU16String& text, int start, int end)
{
    real_->OnSelectionChange(ArkWebU16StringStructToClass(text), start, end);
}

} // namespace OHOS::ArkWeb