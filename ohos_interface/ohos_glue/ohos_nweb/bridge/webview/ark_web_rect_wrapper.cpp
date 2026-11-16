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

#include "ohos_nweb/bridge/ark_web_rect_wrapper.h"

#include "base/bridge/ark_web_bridge_macros.h"

namespace OHOS::ArkWeb {

ArkWebRectWrapper::ArkWebRectWrapper(ArkWebRefPtr<ArkWebRect> ark_web_rect) : ark_web_rect_(ark_web_rect) {}

int ArkWebRectWrapper::GetX()
{
    return ark_web_rect_->GetX();
}

int ArkWebRectWrapper::GetY()
{
    return ark_web_rect_->GetY();
}

int ArkWebRectWrapper::GetWidth()
{
    return ark_web_rect_->GetWidth();
}

int ArkWebRectWrapper::GetHeight()
{
    return ark_web_rect_->GetHeight();
}

} // namespace OHOS::ArkWeb
