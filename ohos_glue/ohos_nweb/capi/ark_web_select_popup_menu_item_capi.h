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

#ifndef ARK_WEB_SELECT_POPUP_MENU_ITEM_CAPI_H_
#define ARK_WEB_SELECT_POPUP_MENU_ITEM_CAPI_H_
#pragma once

#include "base/capi/ark_web_base_ref_counted_capi.h"
#include "base/include/ark_web_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _ark_web_select_popup_menu_item_t {
    /**
     * @brief Base structure.
     */
    ark_web_base_ref_counted_t base;

    int(ARK_WEB_CALLBACK* get_type)(struct _ark_web_select_popup_menu_item_t* self);

    ArkWebString(ARK_WEB_CALLBACK* get_label)(struct _ark_web_select_popup_menu_item_t* self);

    uint32_t(ARK_WEB_CALLBACK* get_action)(struct _ark_web_select_popup_menu_item_t* self);

    ArkWebString(ARK_WEB_CALLBACK* get_tool_tip)(struct _ark_web_select_popup_menu_item_t* self);

    bool(ARK_WEB_CALLBACK* get_is_checked)(struct _ark_web_select_popup_menu_item_t* self);

    bool(ARK_WEB_CALLBACK* get_is_enabled)(struct _ark_web_select_popup_menu_item_t* self);

    int(ARK_WEB_CALLBACK* get_text_direction)(struct _ark_web_select_popup_menu_item_t* self);

    bool(ARK_WEB_CALLBACK* get_has_text_direction_override)(struct _ark_web_select_popup_menu_item_t* self);
} ark_web_select_popup_menu_item_t;

#ifdef __cplusplus
}
#endif

#endif // ARK_WEB_SELECT_POPUP_MENU_ITEM_CAPI_H_
