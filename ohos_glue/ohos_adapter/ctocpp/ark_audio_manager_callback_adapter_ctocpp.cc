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

#include "ctocpp/ark_audio_manager_callback_adapter_ctocpp.h"

#include "ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
void ArkAudioManagerCallbackAdapterCToCpp::OnSuspend()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_audio_manager_callback_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, on_suspend, );

    // Execute
    _struct->on_suspend(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkAudioManagerCallbackAdapterCToCpp::OnResume()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_audio_manager_callback_adapter_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, on_resume, );

    // Execute
    _struct->on_resume(_struct);
}

ArkAudioManagerCallbackAdapterCToCpp::ArkAudioManagerCallbackAdapterCToCpp() {}

ArkAudioManagerCallbackAdapterCToCpp::~ArkAudioManagerCallbackAdapterCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkAudioManagerCallbackAdapterCToCpp, ArkAudioManagerCallbackAdapter,
    ark_audio_manager_callback_adapter_t>::kBridgeType = ARK_AUDIO_MANAGER_CALLBACK_ADAPTER;

} // namespace OHOS::ArkWeb