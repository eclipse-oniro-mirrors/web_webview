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

#include "ohos_nweb/bridge/ark_web_cursor_info_impl.h"

#include "base/bridge/ark_web_bridge_macros.h"

namespace OHOS::ArkWeb {

ArkWebCursorInfoImpl::ArkWebCursorInfoImpl(std::shared_ptr<OHOS::NWeb::NWebCursorInfo> nweb_cursor_info)
    : nweb_cursor_info_(nweb_cursor_info)
{}

int32_t ArkWebCursorInfoImpl::GetX()
{
    return nweb_cursor_info_->GetX();
}

int32_t ArkWebCursorInfoImpl::GetY()
{
    return nweb_cursor_info_->GetY();
}

uint8_t* ArkWebCursorInfoImpl::GetBuff()
{
    return nweb_cursor_info_->GetBuff();
}

float ArkWebCursorInfoImpl::GetScale()
{
    return nweb_cursor_info_->GetScale();
}

int32_t ArkWebCursorInfoImpl::GetWidth()
{
    return nweb_cursor_info_->GetWidth();
}

int32_t ArkWebCursorInfoImpl::GetHeight()
{
    return nweb_cursor_info_->GetHeight();
}

} // namespace OHOS::ArkWeb
