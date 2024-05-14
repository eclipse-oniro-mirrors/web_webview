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

#include "ohos_adapter/cpptoc/ark_ohos_image_decoder_adapter_cpptoc.h"
#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

bool ARK_WEB_CALLBACK ark_ohos_image_decoder_adapter_parse_image_info(
    struct _ark_ohos_image_decoder_adapter_t *self, const uint8_t *data,
    uint32_t size) {
  ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

  ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

  ARK_WEB_CPPTOC_CHECK_PARAM(data, false);

  // Execute
  return ArkOhosImageDecoderAdapterCppToC::Get(self)->ParseImageInfo(data,
                                                                     size);
}

ArkWebString ARK_WEB_CALLBACK ark_ohos_image_decoder_adapter_get_encoded_format(
    struct _ark_ohos_image_decoder_adapter_t *self) {
  ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

  ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_string_default);

  // Execute
  return ArkOhosImageDecoderAdapterCppToC::Get(self)->GetEncodedFormat();
}

int32_t ARK_WEB_CALLBACK ark_ohos_image_decoder_adapter_get_image_width(
    struct _ark_ohos_image_decoder_adapter_t *self) {
  ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

  ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

  // Execute
  return ArkOhosImageDecoderAdapterCppToC::Get(self)->GetImageWidth();
}

int32_t ARK_WEB_CALLBACK ark_ohos_image_decoder_adapter_get_image_height(
    struct _ark_ohos_image_decoder_adapter_t *self) {
  ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

  ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

  // Execute
  return ArkOhosImageDecoderAdapterCppToC::Get(self)->GetImageHeight();
}

bool ARK_WEB_CALLBACK ark_ohos_image_decoder_adapter_decode_to_pixel_map(
    struct _ark_ohos_image_decoder_adapter_t *self, const uint8_t *data,
    uint32_t size) {
  ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

  ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

  ARK_WEB_CPPTOC_CHECK_PARAM(data, false);

  // Execute
  return ArkOhosImageDecoderAdapterCppToC::Get(self)->DecodeToPixelMap(data,
                                                                       size);
}

int32_t ARK_WEB_CALLBACK ark_ohos_image_decoder_adapter_get_fd(
    struct _ark_ohos_image_decoder_adapter_t *self) {
  ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

  ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

  // Execute
  return ArkOhosImageDecoderAdapterCppToC::Get(self)->GetFd();
}

int32_t ARK_WEB_CALLBACK ark_ohos_image_decoder_adapter_get_stride(
    struct _ark_ohos_image_decoder_adapter_t *self) {
  ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

  ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

  // Execute
  return ArkOhosImageDecoderAdapterCppToC::Get(self)->GetStride();
}

int32_t ARK_WEB_CALLBACK ark_ohos_image_decoder_adapter_get_offset(
    struct _ark_ohos_image_decoder_adapter_t *self) {
  ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

  ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

  // Execute
  return ArkOhosImageDecoderAdapterCppToC::Get(self)->GetOffset();
}

uint64_t ARK_WEB_CALLBACK ark_ohos_image_decoder_adapter_get_size(
    struct _ark_ohos_image_decoder_adapter_t *self) {
  ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

  ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

  // Execute
  return ArkOhosImageDecoderAdapterCppToC::Get(self)->GetSize();
}

void *ARK_WEB_CALLBACK ark_ohos_image_decoder_adapter_get_native_window_buffer(
    struct _ark_ohos_image_decoder_adapter_t *self) {
  ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

  ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

  // Execute
  return ArkOhosImageDecoderAdapterCppToC::Get(self)->GetNativeWindowBuffer();
}

int32_t ARK_WEB_CALLBACK ark_ohos_image_decoder_adapter_get_planes_count(
    struct _ark_ohos_image_decoder_adapter_t *self) {
  ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

  ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

  // Execute
  return ArkOhosImageDecoderAdapterCppToC::Get(self)->GetPlanesCount();
}

} // namespace

ArkOhosImageDecoderAdapterCppToC::ArkOhosImageDecoderAdapterCppToC() {
  GetStruct()->parse_image_info =
      ark_ohos_image_decoder_adapter_parse_image_info;
  GetStruct()->get_encoded_format =
      ark_ohos_image_decoder_adapter_get_encoded_format;
  GetStruct()->get_image_width = ark_ohos_image_decoder_adapter_get_image_width;
  GetStruct()->get_image_height =
      ark_ohos_image_decoder_adapter_get_image_height;
  GetStruct()->decode_to_pixel_map =
      ark_ohos_image_decoder_adapter_decode_to_pixel_map;
  GetStruct()->get_fd = ark_ohos_image_decoder_adapter_get_fd;
  GetStruct()->get_stride = ark_ohos_image_decoder_adapter_get_stride;
  GetStruct()->get_offset = ark_ohos_image_decoder_adapter_get_offset;
  GetStruct()->get_size = ark_ohos_image_decoder_adapter_get_size;
  GetStruct()->get_native_window_buffer =
      ark_ohos_image_decoder_adapter_get_native_window_buffer;
  GetStruct()->get_planes_count =
      ark_ohos_image_decoder_adapter_get_planes_count;
}

ArkOhosImageDecoderAdapterCppToC::~ArkOhosImageDecoderAdapterCppToC() {
}

template <>
ArkWebBridgeType ArkWebCppToCRefCounted<
    ArkOhosImageDecoderAdapterCppToC, ArkOhosImageDecoderAdapter,
    ark_ohos_image_decoder_adapter_t>::kBridgeType =
    ARK_OHOS_IMAGE_DECODER_ADAPTER;

} // namespace OHOS::ArkWeb
