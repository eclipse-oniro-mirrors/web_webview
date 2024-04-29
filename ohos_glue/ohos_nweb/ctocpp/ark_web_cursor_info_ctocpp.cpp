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

#include "ohos_nweb/ctocpp/ark_web_cursor_info_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
int32_t ArkWebCursorInfoCToCpp::GetX()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_cursor_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_x, 0);

    // Execute
    return _struct->get_x(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebCursorInfoCToCpp::GetY()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_cursor_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_y, 0);

    // Execute
    return _struct->get_y(_struct);
}

ARK_WEB_NO_SANITIZE
uint8_t* ArkWebCursorInfoCToCpp::GetBuff()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_cursor_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, nullptr);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_buff, nullptr);

    // Execute
    return _struct->get_buff(_struct);
}

ARK_WEB_NO_SANITIZE
float ArkWebCursorInfoCToCpp::GetScale()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_cursor_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_scale, 0);

    // Execute
    return _struct->get_scale(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebCursorInfoCToCpp::GetWidth()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_cursor_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_width, 0);

    // Execute
    return _struct->get_width(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebCursorInfoCToCpp::GetHeight()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_cursor_info_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_height, 0);

    // Execute
    return _struct->get_height(_struct);
}

ArkWebCursorInfoCToCpp::ArkWebCursorInfoCToCpp() {}

ArkWebCursorInfoCToCpp::~ArkWebCursorInfoCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkWebCursorInfoCToCpp, ArkWebCursorInfo, ark_web_cursor_info_t>::kBridgeType =
    ARK_WEB_CURSOR_INFO;

} // namespace OHOS::ArkWeb
