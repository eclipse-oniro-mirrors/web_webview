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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or wrapperied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ARK_WEB_SCREEN_CAPTURE_CONFIG_WRAPPER_H_
#define ARK_WEB_SCREEN_CAPTURE_CONFIG_WRAPPER_H_
#pragma once

#include "include/nweb_access_request.h"
#include "ohos_nweb/include/ark_web_screen_capture_config.h"

#include "base/include/ark_web_types.h"

namespace OHOS::ArkWeb {

class ArkWebScreenCaptureConfigWrapper : public OHOS::NWeb::NWebScreenCaptureConfig {
public:
    ArkWebScreenCaptureConfigWrapper(ArkWebRefPtr<ArkWebScreenCaptureConfig> ark_web_screen_capture_config);
    ~ArkWebScreenCaptureConfigWrapper() = default;

    int32_t GetMode() override;

    int32_t GetSourceId() override;

private:
    ArkWebRefPtr<ArkWebScreenCaptureConfig> ark_web_screen_capture_config_;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_SCREEN_CAPTURE_CONFIG_WRAPPER_H_