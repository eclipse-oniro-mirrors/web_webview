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

#include "ohos_nweb/bridge/ark_web_download_callback_impl.h"

#include "base/bridge/ark_web_bridge_macros.h"

namespace OHOS::ArkWeb {

ArkWebDownloadCallbackImpl::ArkWebDownloadCallbackImpl(
    std::shared_ptr<OHOS::NWeb::NWebDownloadCallback> nweb_download_callback)
    : nweb_download_callback_(nweb_download_callback)
{}

void ArkWebDownloadCallbackImpl::OnDownloadStart(const ArkWebString& url, const ArkWebString& user_agent,
    const ArkWebString& content_disposition, const ArkWebString& mime_type, long content_length)
{
    nweb_download_callback_->OnDownloadStart(ArkWebStringStructToClass(url), ArkWebStringStructToClass(user_agent),
        ArkWebStringStructToClass(content_disposition), ArkWebStringStructToClass(mime_type), content_length);
}

} // namespace OHOS::ArkWeb
