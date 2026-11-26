/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#ifndef ARK_WEB_DEVICE_PERMISSION_RESULT_CALLBACK_IMPL_H
#define ARK_WEB_DEVICE_PERMISSION_RESULT_CALLBACK_IMPL_H
#include "ohos_nweb/include/ark_web_device_permission_delegate.h"
#include "include/nweb_device_permission_delegate.h"
#include "base/include/ark_web_base_ref_counted.h"

namespace OHOS::ArkWeb {

class ArkWebDevicePermissionResultCallbackImpl : public ArkWebDevicePermissionResultCallback {

public:
    explicit ArkWebDevicePermissionResultCallbackImpl(
        std::shared_ptr<OHOS::NWeb::NWebDevicePermissionResultCallback> ref);
    ~ArkWebDevicePermissionResultCallbackImpl() = default;

    void OnSelect(const ArkWebDevicePermissionDeviceIdentifier& device) override;
    void OnCancel() override;

private:
    std::shared_ptr<OHOS::NWeb::NWebDevicePermissionResultCallback> real_;
    IMPLEMENT_REFCOUNTING(ArkWebDevicePermissionResultCallbackImpl);
};
} // namespace OHOS::ArkWeb
#endif // ARK_WEB_DEVICE_PERMISSION_RESULT_CALLBACK_IMPL_H
