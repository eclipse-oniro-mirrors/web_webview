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
#include "ohos_nweb/bridge/ark_web_permission_origins_result_callback_wrapper.h"
#include "base/bridge/ark_web_bridge_macros.h"
#include "base/include/ark_web_types.h"
#include "ohos_nweb/bridge/ark_web_view_struct_utils.h"

namespace OHOS::ArkWeb {

ArkWebPermissionOriginsResultCallbackWrapper::ArkWebPermissionOriginsResultCallbackWrapper(
    ArkWebRefPtr<ArkWebPermissionOriginsResultCallback> ref) : ctocpp_(ref) {}

void ArkWebPermissionOriginsResultCallbackWrapper::OnReply(const std::string& config)
{
    ArkWebString ark_config = ArkWebStringClassToStruct(config);

    ctocpp_->OnReply(ark_config);

    ArkWebStringStructRelease(ark_config);
}

} // namespace OHOS::ArkWeb
