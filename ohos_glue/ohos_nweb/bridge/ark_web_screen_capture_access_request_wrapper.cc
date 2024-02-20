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

#include "ohos_nweb/bridge/ark_web_screen_capture_access_request_wrapper.h"
#include "base/bridge/ark_web_bridge_macros.h"
#include "ohos_nweb/bridge/ark_web_view_struct_utils.h"

namespace OHOS::ArkWeb {

ArkWebScreenCaptureAccessRequestWrapper::
    ArkWebScreenCaptureAccessRequestWrapper(
        ArkWebRefPtr<ArkWebScreenCaptureAccessRequest>
            ark_web_screen_capture_access_request)
    : ark_web_screen_capture_access_request_(
          ark_web_screen_capture_access_request) {
}

void ArkWebScreenCaptureAccessRequestWrapper::Agree(
    const OHOS::NWeb::NWebScreenCaptureConfig &config) {
  ArkWebScreenCaptureConfig ark_web_config =
      ArkWebScreenCaptureConfigClassToStruct(config);
  ark_web_screen_capture_access_request_->Agree(ark_web_config);
}

void ArkWebScreenCaptureAccessRequestWrapper::Refuse() {
  ark_web_screen_capture_access_request_->Refuse();
}

std::string ArkWebScreenCaptureAccessRequestWrapper::Origin() {
  ArkWebString stOrigin = ark_web_screen_capture_access_request_->Origin();

  std::string objOrigin = ArkWebStringStructToClass(stOrigin);
  ArkWebStringStructRelease(stOrigin);
  return objOrigin;
}

} // namespace OHOS::ArkWeb
