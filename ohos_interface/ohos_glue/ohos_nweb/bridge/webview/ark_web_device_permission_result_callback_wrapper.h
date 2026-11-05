/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef ARK_WEB_DEVICE_PERMISSION_RESULT_CALLBACK_WRAPPER_H_
#define ARK_WEB_DEVICE_PERMISSION_RESULT_CALLBACK_WRAPPER_H_
#pragma once

#include "include/nweb_device_permission_delegate.h"
#include "ohos_nweb/include/ark_web_device_permission_delegate.h"

namespace OHOS::ArkWeb {

class ArkWebDevicePermissionResultCallbackWrapper : public OHOS::NWeb::NWebDevicePermissionResultCallback {
public:
    explicit ArkWebDevicePermissionResultCallbackWrapper(
        ArkWebRefPtr<ArkWebDevicePermissionResultCallback> ark_web_device_permission_result_callback);
    ~ArkWebDevicePermissionResultCallbackWrapper() = default;

    void OnSelect(const OHOS::NWeb::NWebDevicePermissionDeviceIdentifier& device) override;

    void OnCancel() override;

private:
    ArkWebRefPtr<ArkWebDevicePermissionResultCallback> ark_web_device_permission_result_callback_;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_DEVICE_PERMISSION_RESULT_CALLBACK_WRAPPER_H_
