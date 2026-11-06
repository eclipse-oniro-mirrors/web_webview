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

#include "ohos_nweb/bridge/ark_web_permission_origins_result_callback_impl.h"

#include "base/bridge/ark_web_bridge_macros.h"
#include "base/include/ark_web_types.h"

namespace OHOS::ArkWeb {

ArkWebPermissionOriginsResultCallbackImpl::ArkWebPermissionOriginsResultCallbackImpl(
    std::shared_ptr<OHOS::NWeb::NWebPermissionOriginsResultCallback> nweb_permission_origins_result_callback)
    : nweb_permission_origins_result_callback_(nweb_permission_origins_result_callback)
{}

void ArkWebPermissionOriginsResultCallbackImpl::OnReply(const ArkWebString& config)
{
    if (CHECK_SHARED_PTR_IS_NULL(nweb_permission_origins_result_callback_)) {
        return;
    }

    std::string class_value = ArkWebStringStructToClass(config);
    nweb_permission_origins_result_callback_->OnReply(class_value);
}

} // namespace OHOS::ArkWeb
