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

#include "ohos_nweb/bridge/ark_web_select_popup_menu_param_wrapper.h"
#include "base/bridge/ark_web_bridge_macros.h"
#include "ohos_nweb/bridge/ark_web_view_struct_utils.h"
#include "ohos_nweb/ctocpp/ark_web_select_popup_menu_item_vector_ctocpp.h"

namespace OHOS::ArkWeb {

ArkWebSelectPopupMenuParamWrapper::ArkWebSelectPopupMenuParamWrapper(
    ArkWebRefPtr<ArkWebSelectPopupMenuParam> ark_web_select_popup_menu_param)
    : ark_web_select_popup_menu_param_(ark_web_select_popup_menu_param) {
}

std::vector<std::shared_ptr<OHOS::NWeb::NWebSelectPopupMenuItem>>
ArkWebSelectPopupMenuParamWrapper::GetMenuItems() {
  ArkWebSelectPopupMenuItemVector stSelectPopupMenuItemVector =
      ark_web_select_popup_menu_param_->GetMenuItems();

  std::vector<std::shared_ptr<OHOS::NWeb::NWebSelectPopupMenuItem>>
      objSelectPopupMenuItemVector =
          ArkWebSelectPopupMenuItemVectorStructToClass(
              stSelectPopupMenuItemVector);
  ArkWebSelectPopupMenuItemVectorStructRelease(stSelectPopupMenuItemVector);
  return objSelectPopupMenuItemVector;
}

int ArkWebSelectPopupMenuParamWrapper::GetItemHeight() {
  return ark_web_select_popup_menu_param_->GetItemHeight();
}

int ArkWebSelectPopupMenuParamWrapper::GetSelectedItem() {
  return ark_web_select_popup_menu_param_->GetSelectedItem();
}

double ArkWebSelectPopupMenuParamWrapper::GetItemFontSize() {
  return ark_web_select_popup_menu_param_->GetItemFontSize();
}

bool ArkWebSelectPopupMenuParamWrapper::GetIsRightAligned() {
  return ark_web_select_popup_menu_param_->GetIsRightAligned();
}

OHOS::NWeb::SelectMenuBound
ArkWebSelectPopupMenuParamWrapper::GetSelectMenuBound() {
  ArkWebSelectMenuBound ark_wen_select_menu_bound =
      ark_web_select_popup_menu_param_->GetSelectMenuBound();
  return ArkWebSelectMenuBoundStructToClass(ark_wen_select_menu_bound);
}

bool ArkWebSelectPopupMenuParamWrapper::GetIsAllowMultipleSelection() {
  return ark_web_select_popup_menu_param_->GetIsAllowMultipleSelection();
}

} // namespace OHOS::ArkWeb