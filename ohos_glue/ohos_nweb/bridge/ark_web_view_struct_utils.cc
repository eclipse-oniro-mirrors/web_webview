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

#include "ohos_nweb/bridge/ark_web_view_struct_utils.h"
#include "base/bridge/ark_web_bridge_macros.h"

namespace OHOS::ArkWeb {

ArkWebDateTime
ArkWebDateTimeClassToStruct(const OHOS::NWeb::DateTime &class_value) {
  ArkWebDateTime struct_value = {.year = class_value.year,
                                 .month = class_value.month,
                                 .day = class_value.day,
                                 .hour = class_value.hour,
                                 .minute = class_value.minute,
                                 .second = class_value.second};
  return struct_value;
}

OHOS::NWeb::DateTime
ArkWebDateTimeStructToClass(const ArkWebDateTime &struct_value) {
  OHOS::NWeb::DateTime class_value = {.year = struct_value.year,
                                      .month = struct_value.month,
                                      .day = struct_value.day,
                                      .hour = struct_value.hour,
                                      .minute = struct_value.minute,
                                      .second = struct_value.second};
  return class_value;
}

ArkWebDragEvent
ArkWebDragEventClassToStruct(const OHOS::NWeb::DragEvent &class_value) {
  ArkWebDragEvent struct_value = {.x = class_value.x, .y = class_value.y};
  struct_value.action = static_cast<int>(class_value.action);
  return struct_value;
}

OHOS::NWeb::NWebCursorInfo
ArkWebCursorInfoStructToClass(const ArkWebCursorInfo &struct_value) {
  OHOS::NWeb::NWebCursorInfo class_value = {.width = struct_value.width,
                                            .height = struct_value.height,
                                            .x = struct_value.x,
                                            .y = struct_value.y,
                                            .scale = struct_value.scale};
  return class_value;
}

OHOS::NWeb::ImageOptions
ArkWebImageOptionsStructToClass(const ArkWebImageOptions &struct_value) {
  OHOS::NWeb::ImageOptions class_value = {.width = struct_value.width,
                                          .height = struct_value.height};
  class_value.alphaType =
      static_cast<OHOS::NWeb::ImageAlphaType>(struct_value.alphaType);
  class_value.colorType =
      static_cast<OHOS::NWeb::ImageColorType>(struct_value.colorType);
  return class_value;
}

OHOS::NWeb::DateTimeChooser
ArkWebDateTimeChooserStructToClass(const ArkWebDateTimeChooser &struct_value) {
  OHOS::NWeb::DateTimeChooser class_value = {
      .step = struct_value.step,
      .suggestionIndex = struct_value.suggestionIndex,
      .hasSelected = struct_value.hasSelected};
  class_value.type =
      static_cast<OHOS::NWeb::DateTimeChooserType>(struct_value.type);
  class_value.minimum = ArkWebDateTimeStructToClass(struct_value.minimum);
  class_value.maximum = ArkWebDateTimeStructToClass(struct_value.maximum);
  class_value.dialogValue =
      ArkWebDateTimeStructToClass(struct_value.dialogValue);
  return class_value;
}

OHOS::NWeb::SelectMenuBound
ArkWebSelectMenuBoundStructToClass(const ArkWebSelectMenuBound &struct_value) {
  OHOS::NWeb::SelectMenuBound class_value = {.x = struct_value.x,
                                             .y = struct_value.y,
                                             .width = struct_value.width,
                                             .height = struct_value.height};
  return class_value;
}

ArkWebTouchHandleHotZone ArkWebTouchHandleHotZoneClassToStruct(
    const OHOS::NWeb::TouchHandleHotZone &class_value) {
  ArkWebTouchHandleHotZone struct_value = {.width = class_value.width,
                                           .height = class_value.height};
  return struct_value;
}

ArkWebScreenCaptureConfig ArkWebScreenCaptureConfigClassToStruct(
    const OHOS::NWeb::NWebScreenCaptureConfig &class_value) {
  ArkWebScreenCaptureConfig struct_value = {.mode = class_value.mode,
                                            .sourceId = class_value.sourceId};
  return struct_value;
}

} // namespace OHOS::ArkWeb
