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

#include "ohos_nweb/cpptoc/ark_web_screen_capture_config_cpptoc.h"
#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

int32_t ARK_WEB_CALLBACK ark_web_screen_capture_config_get_mode(
    struct _ark_web_screen_capture_config_t *self) {
  ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

  ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

  // Execute
  return ArkWebScreenCaptureConfigCppToC::Get(self)->GetMode();
}

int32_t ARK_WEB_CALLBACK ark_web_screen_capture_config_get_source_id(
    struct _ark_web_screen_capture_config_t *self) {
  ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

  ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

  // Execute
  return ArkWebScreenCaptureConfigCppToC::Get(self)->GetSourceId();
}

} // namespace

ArkWebScreenCaptureConfigCppToC::ArkWebScreenCaptureConfigCppToC() {
  GetStruct()->get_mode = ark_web_screen_capture_config_get_mode;
  GetStruct()->get_source_id = ark_web_screen_capture_config_get_source_id;
}

ArkWebScreenCaptureConfigCppToC::~ArkWebScreenCaptureConfigCppToC() {
}

template <>
ArkWebBridgeType ArkWebCppToCRefCounted<
    ArkWebScreenCaptureConfigCppToC, ArkWebScreenCaptureConfig,
    ark_web_screen_capture_config_t>::kBridgeType =
    ARK_WEB_SCREEN_CAPTURE_CONFIG;

} // namespace OHOS::ArkWeb