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

#ifndef ARK_IMF_ADAPTER_CAPI_H
#define ARK_IMF_ADAPTER_CAPI_H
#pragma once

#include "capi/ark_web_base_ref_counted_capi.h"
#include "include/ark_imf_adapter.h"
#include "include/ark_web_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _ark_imfadapter_function_key_adapter_t {
    /**
     * @brief Base structure.
     */
    ark_web_base_ref_counted_t base;

    int32_t(ARK_WEB_CALLBACK* get_enter_key_type)(struct _ark_imfadapter_function_key_adapter_t* self);
} ark_imfadapter_function_key_adapter_t;

typedef struct _ark_imftext_listener_adapter_t {
    /**
     * @brief Base structure.
     */
    ark_web_base_ref_counted_t base;

    void(ARK_WEB_CALLBACK* insert_text)(struct _ark_imftext_listener_adapter_t* self, const ArkWebU16String* text);

    void(ARK_WEB_CALLBACK* delete_forward)(struct _ark_imftext_listener_adapter_t* self, int32_t length);

    void(ARK_WEB_CALLBACK* delete_backward)(struct _ark_imftext_listener_adapter_t* self, int32_t length);

    void(ARK_WEB_CALLBACK* send_key_event_from_input_method)(struct _ark_imftext_listener_adapter_t* self);

    void(ARK_WEB_CALLBACK* send_keyboard_status)(
        struct _ark_imftext_listener_adapter_t* self, const int32_t* keyboardStatus);

    void(ARK_WEB_CALLBACK* send_function_key)(
        struct _ark_imftext_listener_adapter_t* self, ark_imfadapter_function_key_adapter_t* functionKey);

    void(ARK_WEB_CALLBACK* set_keyboard_status)(struct _ark_imftext_listener_adapter_t* self, bool status);

    void(ARK_WEB_CALLBACK* move_cursor)(struct _ark_imftext_listener_adapter_t* self, const uint32_t direction);

    void(ARK_WEB_CALLBACK* handle_set_selection)(
        struct _ark_imftext_listener_adapter_t* self, int32_t start, int32_t end);

    void(ARK_WEB_CALLBACK* handle_extend_action)(struct _ark_imftext_listener_adapter_t* self, int32_t action);

    void(ARK_WEB_CALLBACK* handle_select)(
        struct _ark_imftext_listener_adapter_t* self, int32_t keyCode, int32_t cursorMoveSkip);

    int32_t(ARK_WEB_CALLBACK* get_text_index_at_cursor)(struct _ark_imftext_listener_adapter_t* self);

    ArkWebU16String(ARK_WEB_CALLBACK* get_left_text_of_cursor)(
        struct _ark_imftext_listener_adapter_t* self, int32_t number);

    ArkWebU16String(ARK_WEB_CALLBACK* get_right_text_of_cursor)(
        struct _ark_imftext_listener_adapter_t* self, int32_t number);
} ark_imftext_listener_adapter_t;

typedef struct _ark_imfadapter_t {
    /**
     * @brief Base structure.
     */
    ark_web_base_ref_counted_t base;

    bool(ARK_WEB_CALLBACK* attach1)(
        struct _ark_imfadapter_t* self, ark_imftext_listener_adapter_t* listener, bool isShowKeyboard);

    bool(ARK_WEB_CALLBACK* attach2)(struct _ark_imfadapter_t* self, ark_imftext_listener_adapter_t* listener,
        bool isShowKeyboard, const ArkIMFAdapterTextConfig* config);

    void(ARK_WEB_CALLBACK* show_current_input)(struct _ark_imfadapter_t* self, const int32_t* inputType);

    void(ARK_WEB_CALLBACK* hide_text_input)(struct _ark_imfadapter_t* self);

    void(ARK_WEB_CALLBACK* close)(struct _ark_imfadapter_t* self);

    void(ARK_WEB_CALLBACK* on_cursor_update)(struct _ark_imfadapter_t* self, ArkIMFAdapterCursorInfo cursorInfo);

    void(ARK_WEB_CALLBACK* on_selection_change)(
        struct _ark_imfadapter_t* self, ArkWebU16String* text, int start, int end);
} ark_imfadapter_t;

#ifdef __cplusplus
}
#endif

#endif // ARK_IMF_ADAPTER_CAPI_H