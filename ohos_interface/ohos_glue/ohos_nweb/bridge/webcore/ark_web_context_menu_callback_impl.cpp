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

#include "ohos_nweb/bridge/ark_web_context_menu_callback_impl.h"

#include "base/bridge/ark_web_bridge_macros.h"

namespace OHOS::ArkWeb {

using ArkWebMenuEventFlags = OHOS::NWeb::MenuEventFlags;

ArkWebContextMenuCallbackImpl::ArkWebContextMenuCallbackImpl(
    std::shared_ptr<OHOS::NWeb::NWebContextMenuCallback> nweb_context_menu_callback)
    : nweb_context_menu_callback_(nweb_context_menu_callback)
{}

void ArkWebContextMenuCallbackImpl::Cancel()
{
    nweb_context_menu_callback_->Cancel();
}

void ArkWebContextMenuCallbackImpl::Continue(int32_t command_id, int flag)
{
    nweb_context_menu_callback_->Continue(command_id, static_cast<ArkWebMenuEventFlags>(flag));
}

} // namespace OHOS::ArkWeb