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

#include "ohos_nweb/ctocpp/ark_web_touch_handle_state_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
int32_t ArkWebTouchHandleStateCToCpp::GetX()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_touch_handle_state_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_x, 0);

    // Execute
    return _struct->get_x(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebTouchHandleStateCToCpp::GetY()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_touch_handle_state_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_y, 0);

    // Execute
    return _struct->get_y(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebTouchHandleStateCToCpp::IsEnable()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_touch_handle_state_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, is_enable, false);

    // Execute
    return _struct->is_enable(_struct);
}

ARK_WEB_NO_SANITIZE
float ArkWebTouchHandleStateCToCpp::GetAlpha()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_touch_handle_state_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_alpha, 0);

    // Execute
    return _struct->get_alpha(_struct);
}

ARK_WEB_NO_SANITIZE
float ArkWebTouchHandleStateCToCpp::GetEdgeHeight()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_touch_handle_state_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_edge_height, 0);

    // Execute
    return _struct->get_edge_height(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebTouchHandleStateCToCpp::GetViewPortX()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_touch_handle_state_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_view_port_x, 0);

    // Execute
    return _struct->get_view_port_x(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebTouchHandleStateCToCpp::GetViewPortY()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_touch_handle_state_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_view_port_y, 0);

    // Execute
    return _struct->get_view_port_y(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebTouchHandleStateCToCpp::GetTouchHandleId()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_touch_handle_state_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_touch_handle_id, 0);

    // Execute
    return _struct->get_touch_handle_id(_struct);
}

ARK_WEB_NO_SANITIZE
int ArkWebTouchHandleStateCToCpp::GetTouchHandleType()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_touch_handle_state_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_touch_handle_type, 0);

    // Execute
    return _struct->get_touch_handle_type(_struct);
}

ArkWebTouchHandleStateCToCpp::ArkWebTouchHandleStateCToCpp() {}

ArkWebTouchHandleStateCToCpp::~ArkWebTouchHandleStateCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkWebTouchHandleStateCToCpp, ArkWebTouchHandleState,
    ark_web_touch_handle_state_t>::kBridgeType = ARK_WEB_TOUCH_HANDLE_STATE;

} // namespace OHOS::ArkWeb
