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

#ifndef ARK_WEB_ACCESSIBILITY_NODE_INFO_WRAPPER_H_
#define ARK_WEB_ACCESSIBILITY_NODE_INFO_WRAPPER_H_
#pragma once

#include "include/nweb_accessibility_node_info.h"
#include "ohos_nweb/include/ark_web_accessibility_node_info.h"

namespace OHOS::ArkWeb {

class ArkWebAccessibilityNodeInfoWrapper : public OHOS::NWeb::NWebAccessibilityNodeInfo {
public:
    ArkWebAccessibilityNodeInfoWrapper(ArkWebRefPtr<ArkWebAccessibilityNodeInfo> ark_web_accessibility_node_info);
    ~ArkWebAccessibilityNodeInfoWrapper() = default;

    std::string GetHint() override;

    std::string GetError() override;

    int32_t GetRectX() override;

    int32_t GetRectY() override;

    void SetPageId(int32_t page_id) override;

    int32_t GetPageId() override;

    std::vector<uint32_t> GetActions() override;

    std::string GetContent() override;

    std::vector<int64_t> GetChildIds() override;

    void SetParentId(int64_t parent_id) override;

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

    std::string GetComponentType() override;

    std::string GetDescriptionInfo() override;

    int32_t GetGridRows() override;

    int32_t GetGridItemRow() override;

    int32_t GetGridColumns() override;

    int32_t GetGridItemColumn() override;

    int32_t GetGridItemRowSpan() override;

    int32_t GetGridSelectedMode() override;

    int32_t GetGridItemColumnSpan() override;

    bool GetIsAccessibilityFocus() override;

    bool GetIsPluralLineSupported() override;

private:
    ArkWebRefPtr<ArkWebAccessibilityNodeInfo> ark_web_accessibility_node_info_;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_ACCESSIBILITY_NODE_INFO_WRAPPER_H_
