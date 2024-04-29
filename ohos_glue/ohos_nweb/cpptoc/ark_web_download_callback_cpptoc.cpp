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

#include "ohos_nweb/cpptoc/ark_web_download_callback_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

void ARK_WEB_CALLBACK ark_web_download_callback_on_download_start(struct _ark_web_download_callback_t* self,
    const ArkWebString* url, const ArkWebString* user_agent, const ArkWebString* content_disposition,
    const ArkWebString* mime_type, long content_length)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    ARK_WEB_CPPTOC_CHECK_PARAM(url, );

    ARK_WEB_CPPTOC_CHECK_PARAM(user_agent, );

    ARK_WEB_CPPTOC_CHECK_PARAM(content_disposition, );

    ARK_WEB_CPPTOC_CHECK_PARAM(mime_type, );

    // Execute
    ArkWebDownloadCallbackCppToC::Get(self)->OnDownloadStart(
        *url, *user_agent, *content_disposition, *mime_type, content_length);
}

} // namespace

ArkWebDownloadCallbackCppToC::ArkWebDownloadCallbackCppToC()
{
    GetStruct()->on_download_start = ark_web_download_callback_on_download_start;
}

ArkWebDownloadCallbackCppToC::~ArkWebDownloadCallbackCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkWebDownloadCallbackCppToC, ArkWebDownloadCallback,
    ark_web_download_callback_t>::kBridgeType = ARK_WEB_DOWNLOAD_CALLBACK;

} // namespace OHOS::ArkWeb
