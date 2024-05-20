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

#ifndef ARK_WEB_ACCESSIBILITY_NODE_INFO_CTOCPP_H_
#define ARK_WEB_ACCESSIBILITY_NODE_INFO_CTOCPP_H_
#pragma once

#include "ohos_nweb/capi/ark_web_accessibility_node_info_capi.h"
#include "ohos_nweb/include/ark_web_accessibility_node_info.h"

#include "base/ctocpp/ark_web_ctocpp_ref_counted.h"

namespace OHOS::ArkWeb {

// Wrap a C structure with a C++ class.
// This class may be instantiated and accessed wrapper-side only.
class ArkWebAccessibilityNodeInfoCToCpp : public ArkWebCToCppRefCounted<ArkWebAccessibilityNodeInfoCToCpp,
                                              ArkWebAccessibilityNodeInfo, ark_web_accessibility_node_info_t> {
public:
    ArkWebAccessibilityNodeInfoCToCpp();
    virtual ~ArkWebAccessibilityNodeInfoCToCpp();

    // ArkWebAccessibilityNodeInfo methods.
    ArkWebString GetHint() override;

    ArkWebString GetError() override;

    int32_t GetRectX() override;

    int32_t GetRectY() override;

    void SetPageId(int32_t page_id) override;

    int32_t GetPageId() override;

    ArkWebUint32Vector GetActions() override;

    ArkWebString GetContent() override;

    ArkWebInt64Vector GetChildIds() override;

    void SetParentId(int64_t parentId_id) override;

    int64_t GetParentId() override;

    bool GetIsHeading() override;

    bool GetIsChecked() override;

    bool GetIsEnabled() override;

    bool GetIsFocused() override;

    int32_t GetRectWidth() override;

    int32_t GetRectHeight() override;

    bool GetIsVisible() override;

    bool GetIsHinting() override;

    bool GetIsEditable() override;

    bool GetIsSelected() override;

    size_t GetItemCounts() override;

    int32_t GetLiveRegion() override;

    bool GetIsPassword() override;

    bool GetIsCheckable() override;

    bool GetIsClickable() override;

    bool GetIsFocusable() override;

    bool GetIsScrollable() override;

    bool GetIsDeletable() override;

    int64_t GetAccessibilityId() override;

    bool GetIsPopupSupported() override;

    bool GetIsContentInvalid() override;

    int32_t GetSelectionEnd() override;

    int32_t GetSelectionStart() override;

    float GetRangeInfoMin() override;

    float GetRangeInfoMax() override;

    float GetRangeInfoCurrent() override;

    int32_t GetInputType() override;

    ArkWebString GetComponentType() override;

    ArkWebString GetDescriptionInfo() override;

    int32_t GetGridRows() override;

    int32_t GetGridItemRow() override;

    int32_t GetGridColumns() override;

    int32_t GetGridItemColumn() override;

    int32_t GetGridItemRowSpan() override;

    int32_t GetGridSelectedMode() override;

    int32_t GetGridItemColumnSpan() override;

    bool GetIsAccessibilityFocus() override;

    bool GetIsPluralLineSupported() override;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_ACCESSIBILITY_NODE_INFO_CTOCPP_H_
