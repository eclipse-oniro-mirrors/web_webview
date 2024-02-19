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

#ifndef ARK_IMF_ADAPTER_H
#define ARK_IMF_ADAPTER_H

#pragma once

#include <cstdint>

#include "imf_adapter.h"
#include "include/ark_web_base_ref_counted.h"
#include "include/ark_web_types.h"

using ArkIMFAdapterCursorInfo = OHOS::NWeb::IMFAdapterCursorInfo;
using ArkIMFAdapterInputAttribute = OHOS::NWeb::IMFAdapterInputAttribute;
using ArkIMFAdapterSelectionRange = OHOS::NWeb::IMFAdapterSelectionRange;
using ArkIMFAdapterTextConfig = OHOS::NWeb::IMFAdapterTextConfig;

namespace OHOS::ArkWeb {

/*--web engine(source=library)--*/
class ArkIMFAdapterFunctionKeyAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkIMFAdapterFunctionKeyAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkIMFAdapterFunctionKeyAdapter() = default;

    /*--web engine()--*/
    virtual int32_t GetEnterKeyType() = 0;
};

/*--web engine(source=client)--*/
class ArkIMFTextListenerAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkIMFTextListenerAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkIMFTextListenerAdapter() = default;

    /*--web engine()--*/
    virtual void InsertText(const ArkWebU16String& text) = 0;

    /*--web engine()--*/
    virtual void DeleteForward(int32_t length) = 0;

    /*--web engine()--*/
    virtual void DeleteBackward(int32_t length) = 0;

    /*--web engine()--*/
    virtual void SendKeyEventFromInputMethod() = 0;

    /*--web engine()--*/
    virtual void SendKeyboardStatus(const int32_t& keyboardStatus) = 0;

    /*--web engine()--*/
    virtual void SendFunctionKey(ArkWebRefPtr<ArkIMFAdapterFunctionKeyAdapter> functionKey) = 0;

    /*--web engine()--*/
    virtual void SetKeyboardStatus(bool status) = 0;

    /*--web engine()--*/
    virtual void MoveCursor(const uint32_t direction) = 0;

    /*--web engine()--*/
    virtual void HandleSetSelection(int32_t start, int32_t end) = 0;

    /*--web engine()--*/
    virtual void HandleExtendAction(int32_t action) = 0;

    /*--web engine()--*/
    virtual void HandleSelect(int32_t keyCode, int32_t cursorMoveSkip) = 0;

    /*--web engine()--*/
    virtual int32_t GetTextIndexAtCursor() = 0;

    /*--web engine()--*/
    virtual ArkWebU16String GetLeftTextOfCursor(int32_t number) = 0;

    /*--web engine()--*/
    virtual ArkWebU16String GetRightTextOfCursor(int32_t number) = 0;
};

/*--web engine(source=library)--*/
class ArkIMFAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkIMFAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkIMFAdapter() = default;

    /*--web engine()--*/
    virtual bool Attach(ArkWebRefPtr<ArkIMFTextListenerAdapter> listener, bool isShowKeyboard) = 0;

    /*--web engine()--*/
    virtual bool Attach(ArkWebRefPtr<ArkIMFTextListenerAdapter> listener, bool isShowKeyboard,
        const ArkIMFAdapterTextConfig& config) = 0;

    /*--web engine()--*/
    virtual void ShowCurrentInput(const int32_t& inputType) = 0;

    /*--web engine()--*/
    virtual void HideTextInput() = 0;

    /*--web engine()--*/
    virtual void Close() = 0;

    /*--web engine()--*/
    virtual void OnCursorUpdate(ArkIMFAdapterCursorInfo cursorInfo) = 0;

    /*--web engine()--*/
    virtual void OnSelectionChange(ArkWebU16String& text, int start, int end) = 0;
};
} // namespace OHOS::ArkWeb

#endif // ARK_IMF_ADAPTER_H
