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

#include "ohos_nweb/ctocpp/ark_web_date_time_suggestion_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebDateTimeSuggestionCToCpp::GetLabel()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_date_time_suggestion_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_label, ark_web_string_default);

    // Execute
    return _struct->get_label(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebDateTime ArkWebDateTimeSuggestionCToCpp::GetValue()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_date_time_suggestion_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_date_time_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_value, ark_web_date_time_default);

    // Execute
    return _struct->get_value(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebDateTimeSuggestionCToCpp::GetLocalizedValue()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_date_time_suggestion_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_localized_value, ark_web_string_default);

    // Execute
    return _struct->get_localized_value(_struct);
}

ArkWebDateTimeSuggestionCToCpp::ArkWebDateTimeSuggestionCToCpp() {}

ArkWebDateTimeSuggestionCToCpp::~ArkWebDateTimeSuggestionCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkWebDateTimeSuggestionCToCpp, ArkWebDateTimeSuggestion,
    ark_web_date_time_suggestion_t>::kBridgeType = ARK_WEB_DATE_TIME_SUGGESTION;

} // namespace OHOS::ArkWeb
