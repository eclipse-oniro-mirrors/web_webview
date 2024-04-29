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

#include "ohos_nweb/ctocpp/ark_web_controller_handler_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
int32_t ArkWebControllerHandlerCToCpp::GetId()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_controller_handler_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_id, 0);

    // Execute
    return _struct->get_id(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebControllerHandlerCToCpp::IsFrist()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_controller_handler_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, is_frist, false);

    // Execute
    return _struct->is_frist(_struct);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebControllerHandlerCToCpp::GetNWebHandlerId()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_controller_handler_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_nweb_handler_id, 0);

    // Execute
    return _struct->get_nweb_handler_id(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebControllerHandlerCToCpp::SetNWebHandlerById(int32_t nweb_id)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_controller_handler_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_nweb_handler_by_id, );

    // Execute
    _struct->set_nweb_handler_by_id(_struct, nweb_id);
}

ArkWebControllerHandlerCToCpp::ArkWebControllerHandlerCToCpp() {}

ArkWebControllerHandlerCToCpp::~ArkWebControllerHandlerCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkWebControllerHandlerCToCpp, ArkWebControllerHandler,
    ark_web_controller_handler_t>::kBridgeType = ARK_WEB_CONTROLLER_HANDLER;

} // namespace OHOS::ArkWeb
