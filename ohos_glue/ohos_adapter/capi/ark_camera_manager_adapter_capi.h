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

#ifndef ARK_CAMERA_MANAGER_ADAPTER_CAPI_H
#define ARK_CAMERA_MANAGER_ADAPTER_CAPI_H
#pragma once

#include "capi/ark_web_base_ref_counted_capi.h"
#include "include/ark_camera_manager_adapter.h"
#include "include/ark_web_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _ark_camera_surface_buffer_adapter_t {
    /**
     * @brief Base structure.
     */
    ark_web_base_ref_counted_t base;

    int32_t(ARK_WEB_CALLBACK* get_file_descriptor)(struct _ark_camera_surface_buffer_adapter_t* self);

    int32_t(ARK_WEB_CALLBACK* get_width)(struct _ark_camera_surface_buffer_adapter_t* self);

    int32_t(ARK_WEB_CALLBACK* get_height)(struct _ark_camera_surface_buffer_adapter_t* self);

    int32_t(ARK_WEB_CALLBACK* get_stride)(struct _ark_camera_surface_buffer_adapter_t* self);

    int32_t(ARK_WEB_CALLBACK* get_format)(struct _ark_camera_surface_buffer_adapter_t* self);

    uint32_t(ARK_WEB_CALLBACK* get_size)(struct _ark_camera_surface_buffer_adapter_t* self);

    uint8_t*(ARK_WEB_CALLBACK* get_buffer_addr)(struct _ark_camera_surface_buffer_adapter_t* self);
} ark_camera_surface_buffer_adapter_t;

typedef struct _ark_camera_surface_adapter_t {
    /**
     * @brief Base structure.
     */
    ark_web_base_ref_counted_t base;

    int32_t(ARK_WEB_CALLBACK* release_buffer)(
        struct _ark_camera_surface_adapter_t* self, ark_camera_surface_buffer_adapter_t* buffer, int32_t fence);
} ark_camera_surface_adapter_t;

typedef struct _ark_camera_buffer_listener_adapter_t {
    /**
     * @brief Base structure.
     */
    ark_web_base_ref_counted_t base;

    void(ARK_WEB_CALLBACK* on_buffer_available)(struct _ark_camera_buffer_listener_adapter_t* self,
        ark_camera_surface_adapter_t* surface, ark_camera_surface_buffer_adapter_t* buffer,
        ArkCameraRotationInfo rotationInfo);
} ark_camera_buffer_listener_adapter_t;

typedef struct _ark_camera_status_callback_adapter_t {
    /**
     * @brief Base structure.
     */
    ark_web_base_ref_counted_t base;

    void(ARK_WEB_CALLBACK* on_camera_status_changed)(struct _ark_camera_status_callback_adapter_t* self,
        int32_t cameraStatusAdapter, const ArkWebString callBackDeviceId);
} ark_camera_status_callback_adapter_t;

typedef struct _ark_camera_manager_adapter_t {
    /**
     * @brief Base structure.
     */
    ark_web_base_ref_counted_t base;

    int32_t(ARK_WEB_CALLBACK* create)(
        struct _ark_camera_manager_adapter_t* self, ark_camera_status_callback_adapter_t* cameraStatusCallback);

    void(ARK_WEB_CALLBACK* get_devices_info)(struct _ark_camera_manager_adapter_t* self, void* devicesDiscriptor);

    int32_t(ARK_WEB_CALLBACK* release_camera_manger)(struct _ark_camera_manager_adapter_t* self);

    int32_t(ARK_WEB_CALLBACK* get_exposure_modes)(
        struct _ark_camera_manager_adapter_t* self, ArkWebInt32Vector* exposureModesAdapter);

    int32_t(ARK_WEB_CALLBACK* get_current_exposure_mode)(
        struct _ark_camera_manager_adapter_t* self, int32_t* exposureModeAdapter);

    int32_t(ARK_WEB_CALLBACK* get_caption_range_by_id)(
        struct _ark_camera_manager_adapter_t* self, int32_t rangeId, ArkVideoCaptureRangeAdapter* rangeVal);

    bool(ARK_WEB_CALLBACK* is_focus_mode_supported)(struct _ark_camera_manager_adapter_t* self, int32_t focusMode);

    int32_t(ARK_WEB_CALLBACK* get_current_focus_mode)(struct _ark_camera_manager_adapter_t* self);

    bool(ARK_WEB_CALLBACK* is_flash_mode_supported)(struct _ark_camera_manager_adapter_t* self, int32_t flashMode);

    int32_t(ARK_WEB_CALLBACK* restart_session)(struct _ark_camera_manager_adapter_t* self);

    int32_t(ARK_WEB_CALLBACK* stop_session)(struct _ark_camera_manager_adapter_t* self, int32_t stopType);

    int32_t(ARK_WEB_CALLBACK* get_camera_status)(struct _ark_camera_manager_adapter_t* self);

    bool(ARK_WEB_CALLBACK* is_exist_capture_task)(struct _ark_camera_manager_adapter_t* self);

    int32_t(ARK_WEB_CALLBACK* start_stream)(struct _ark_camera_manager_adapter_t* self, const ArkWebString* deviceId,
        const ArkVideoCaptureParamsAdapter* captureParams, ark_camera_buffer_listener_adapter_t* listener);

    void(ARK_WEB_CALLBACK* set_foreground_flag)(struct _ark_camera_manager_adapter_t* self, bool isForeground);

    void(ARK_WEB_CALLBACK* set_camera_status)(struct _ark_camera_manager_adapter_t* self, int32_t status);

    ArkWebString(ARK_WEB_CALLBACK* get_current_device_id)(struct _ark_camera_manager_adapter_t* self);
} ark_camera_manager_adapter_t;

#ifdef __cplusplus
}
#endif

#endif // ARK_CAMERA_MANAGER_ADAPTER_CAPI_H
