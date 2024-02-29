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

#ifndef ARK_GRAPHIC_ADAPTER_CAPI_H
#define ARK_GRAPHIC_ADAPTER_CAPI_H
#pragma once

#include "capi/ark_web_base_ref_counted_capi.h"
#include "include/ark_graphic_adapter.h"
#include "include/ark_web_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _ark_vsync_adapter_t {
    /**
     * @brief Base structure.
     */
    ark_web_base_ref_counted_t base;

    uint32_t(ARK_WEB_CALLBACK* request_vsync)(struct _ark_vsync_adapter_t* self, void* data, ArkVSyncCb cb);

    int64_t(ARK_WEB_CALLBACK* get_vsync_period)(struct _ark_vsync_adapter_t* self);
} ark_vsync_adapter_t;

typedef struct _ark_surface_buffer_adapter_t {
    /**
     * @brief Base structure.
     */
    ark_web_base_ref_counted_t base;

    int32_t(ARK_WEB_CALLBACK* get_file_descriptor)(struct _ark_surface_buffer_adapter_t* self);

    int32_t(ARK_WEB_CALLBACK* get_width)(struct _ark_surface_buffer_adapter_t* self);

    int32_t(ARK_WEB_CALLBACK* get_height)(struct _ark_surface_buffer_adapter_t* self);

    int32_t(ARK_WEB_CALLBACK* get_stride)(struct _ark_surface_buffer_adapter_t* self);

    int32_t(ARK_WEB_CALLBACK* get_format)(struct _ark_surface_buffer_adapter_t* self);

    uint32_t(ARK_WEB_CALLBACK* get_size)(struct _ark_surface_buffer_adapter_t* self);

    void*(ARK_WEB_CALLBACK* get_vir_addr)(struct _ark_surface_buffer_adapter_t* self);
} ark_surface_buffer_adapter_t;

typedef struct _ark_ibuffer_consumer_listener_adapter_t {
    /**
     * @brief Base structure.
     */
    ark_web_base_ref_counted_t base;

    void(ARK_WEB_CALLBACK* on_buffer_available)(
        struct _ark_ibuffer_consumer_listener_adapter_t* self, ark_surface_buffer_adapter_t* buffer);
} ark_ibuffer_consumer_listener_adapter_t;

typedef struct _ark_iconsumer_surface_adapter_t {
    /**
     * @brief Base structure.
     */
    ark_web_base_ref_counted_t base;

    int32_t(ARK_WEB_CALLBACK* register_consumer_listener)(
        struct _ark_iconsumer_surface_adapter_t* self, ark_ibuffer_consumer_listener_adapter_t* listener);

    int32_t(ARK_WEB_CALLBACK* release_buffer)(
        struct _ark_iconsumer_surface_adapter_t* self, ark_surface_buffer_adapter_t* buffer, int32_t fence);

    int32_t(ARK_WEB_CALLBACK* set_user_data)(
        struct _ark_iconsumer_surface_adapter_t* self, const ArkWebString* key, const ArkWebString* val);

    int32_t(ARK_WEB_CALLBACK* set_queue_size)(struct _ark_iconsumer_surface_adapter_t* self, uint32_t queueSize);
} ark_iconsumer_surface_adapter_t;

typedef struct _ark_window_adapter_t {
    /**
     * @brief Base structure.
     */
    ark_web_base_ref_counted_t base;

    void*(ARK_WEB_CALLBACK* create_native_window_from_surface)(struct _ark_window_adapter_t* self, void* pSurface);

    void(ARK_WEB_CALLBACK* destroy_native_window)(struct _ark_window_adapter_t* self, void* window);

    int32_t(ARK_WEB_CALLBACK* native_window_set_buffer_geometry)(
        struct _ark_window_adapter_t* self, void* window, int32_t width, int32_t height);
} ark_window_adapter_t;

typedef struct _ark_ashmem_adapter_t {
    /**
     * @brief Base structure.
     */
    ark_web_base_ref_counted_t base;
} ark_ashmem_adapter_t;

ARK_WEB_EXPORT int ark_ashmem_adapter_ashmem_create(const char* name, size_t size);

typedef struct _ark_native_image_adapter_t {
    /**
     * @brief Base structure.
     */
    ark_web_base_ref_counted_t base;

    void(ARK_WEB_CALLBACK* create_native_image)(
        struct _ark_native_image_adapter_t* self, uint32_t textureId, uint32_t textureTarget);

    void*(ARK_WEB_CALLBACK* aquire_native_window_from_native_image)(struct _ark_native_image_adapter_t* self);

    int32_t(ARK_WEB_CALLBACK* attach_context)(struct _ark_native_image_adapter_t* self, uint32_t textureId);

    int32_t(ARK_WEB_CALLBACK* detach_context)(struct _ark_native_image_adapter_t* self);

    int32_t(ARK_WEB_CALLBACK* update_surface_image)(struct _ark_native_image_adapter_t* self);

    int64_t(ARK_WEB_CALLBACK* get_timestamp)(struct _ark_native_image_adapter_t* self);

    int32_t(ARK_WEB_CALLBACK* get_transform_matrix)(struct _ark_native_image_adapter_t* self, float matrix[16]);

    int32_t(ARK_WEB_CALLBACK* get_surface_id)(struct _ark_native_image_adapter_t* self, uint64_t* surfaceId);

    int32_t(ARK_WEB_CALLBACK* set_on_frame_available_listener)(
        struct _ark_native_image_adapter_t* self, ArkOnFrameAvailableListener* listener);

    int32_t(ARK_WEB_CALLBACK* unset_on_frame_available_listener)(struct _ark_native_image_adapter_t* self);

    void(ARK_WEB_CALLBACK* destroy_native_image)(struct _ark_native_image_adapter_t* self);
} ark_native_image_adapter_t;

typedef struct _ark_producer_surface_adapter_t {
  /**
   * @brief Base structure.
   */
  ark_web_base_ref_counted_t base;

  ark_surface_buffer_adapter_t* (ARK_WEB_CALLBACK *request_buffer)(struct _ark_producer_surface_adapter_t* self, int32_t* fence, ArkBufferRequestConfigAdapter* config);

  int32_t (ARK_WEB_CALLBACK *flush_buffer)(struct _ark_producer_surface_adapter_t* self, ark_surface_buffer_adapter_t* buffer, int32_t fence, ArkBufferFlushConfigAdapter* flushConfig);
} ark_producer_surface_adapter_t;
#ifdef __cplusplus
}
#endif

#endif // ARK_GRAPHIC_ADAPTER_CAPI_H
