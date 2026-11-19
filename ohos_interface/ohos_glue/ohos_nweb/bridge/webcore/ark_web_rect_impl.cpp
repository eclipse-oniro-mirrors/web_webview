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

#include "ohos_nweb/bridge/ark_web_rect_impl.h"

#include "base/bridge/ark_web_bridge_macros.h"

namespace OHOS::ArkWeb {

ArkWebRectImpl::ArkWebRectImpl(std::shared_ptr<OHOS::NWeb::NWebRect> nweb_rect) : nweb_rect_(nweb_rect) {}

int ArkWebRectImpl::GetX()
{
    return nweb_rect_->GetX();
}

int ArkWebRectImpl::GetY()
{
    return nweb_rect_->GetY();
}

int ArkWebRectImpl::GetWidth()
{
    return nweb_rect_->GetWidth();
}

int ArkWebRectImpl::GetHeight()
{
    return nweb_rect_->GetHeight();
}

} // namespace OHOS::ArkWeb
