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

#ifndef ARK_SCREEN_CAPTURE_ADAPTER_CAPI_H
#define ARK_SCREEN_CAPTURE_ADAPTER_CAPI_H
#pragma once

#include "capi/ark_graphic_adapter_capi.h"
#include "capi/ark_web_base_ref_counted_capi.h"
#include "include/ark_screen_capture_adapter.h"
#include "include/ark_web_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _ark_screen_capture_callback_adapter_t {
    /**
     * @brief Base structure.
     */
    ark_web_base_ref_counted_t base;

    void(ARK_WEB_CALLBACK* on_error)(struct _ark_screen_capture_callback_adapter_t* self, int32_t errorCode);

    void(ARK_WEB_CALLBACK* on_audio_buffer_available)(
        struct _ark_screen_capture_callback_adapter_t* self, bool isReady, int32_t type);

    void(ARK_WEB_CALLBACK* on_video_buffer_available)(
        struct _ark_screen_capture_callback_adapter_t* self, bool isReady);
} ark_screen_capture_callback_adapter_t;

typedef struct _ark_screen_capture_adapter_t {
    /**
     * @brief Base structure.
     */
    ark_web_base_ref_counted_t base;

    int32_t(ARK_WEB_CALLBACK* init)(
        struct _ark_screen_capture_adapter_t* self, const ArkScreenCaptureConfigAdapter* config);

    int32_t(ARK_WEB_CALLBACK* set_microphone_enable)(struct _ark_screen_capture_adapter_t* self, bool enable);

    int32_t(ARK_WEB_CALLBACK* start_capture)(struct _ark_screen_capture_adapter_t* self);

    int32_t(ARK_WEB_CALLBACK* stop_capture)(struct _ark_screen_capture_adapter_t* self);

    int32_t(ARK_WEB_CALLBACK* set_capture_callback)(
        struct _ark_screen_capture_adapter_t* self, ark_screen_capture_callback_adapter_t* callback);

    ark_surface_buffer_adapter_t*(ARK_WEB_CALLBACK* acquire_video_buffer)(struct _ark_screen_capture_adapter_t* self);

    int32_t(ARK_WEB_CALLBACK* release_video_buffer)(struct _ark_screen_capture_adapter_t* self);
} ark_screen_capture_adapter_t;

#ifdef __cplusplus
}
#endif

#endif // ARK_SCREEN_CAPTURE_ADAPTER_CAPI_H
