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

#ifndef ARK_OHOS_IMAGE_DECODER_ADAPTER_CAPI_H_
#define ARK_OHOS_IMAGE_DECODER_ADAPTER_CAPI_H_
#pragma once

#include "base/capi/ark_web_base_ref_counted_capi.h"
#include "base/include/ark_web_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _ark_ohos_image_decoder_adapter_t {
  /**
   * @brief Base structure.
   */
  ark_web_base_ref_counted_t base;

  bool(ARK_WEB_CALLBACK *parse_image_info)(
      struct _ark_ohos_image_decoder_adapter_t *self, const uint8_t *data,
      uint32_t size);

  ArkWebString(ARK_WEB_CALLBACK *get_encoded_format)(
      struct _ark_ohos_image_decoder_adapter_t *self);

  int32_t(ARK_WEB_CALLBACK *get_image_width)(
      struct _ark_ohos_image_decoder_adapter_t *self);

  int32_t(ARK_WEB_CALLBACK *get_image_height)(
      struct _ark_ohos_image_decoder_adapter_t *self);

  bool(ARK_WEB_CALLBACK *decode_to_pixel_map)(
      struct _ark_ohos_image_decoder_adapter_t *self, const uint8_t *data,
      uint32_t size);

  int32_t(ARK_WEB_CALLBACK *get_fd)(
      struct _ark_ohos_image_decoder_adapter_t *self);

  int32_t(ARK_WEB_CALLBACK *get_stride)(
      struct _ark_ohos_image_decoder_adapter_t *self);

  int32_t(ARK_WEB_CALLBACK *get_offset)(
      struct _ark_ohos_image_decoder_adapter_t *self);

  uint64_t(ARK_WEB_CALLBACK *get_size)(
      struct _ark_ohos_image_decoder_adapter_t *self);

  void *(ARK_WEB_CALLBACK *get_native_window_buffer)(
      struct _ark_ohos_image_decoder_adapter_t *self);

  int32_t(ARK_WEB_CALLBACK *get_planes_count)(
      struct _ark_ohos_image_decoder_adapter_t *self);
} ark_ohos_image_decoder_adapter_t;

#ifdef __cplusplus
}
#endif

#endif // ARK_OHOS_IMAGE_DECODER_ADAPTER_CAPI_H_
