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

#ifndef ARK_WEB_DOWNLOAD_CALLBACK_WRAPPER_H_
#define ARK_WEB_DOWNLOAD_CALLBACK_WRAPPER_H_
#pragma once

#include "include/nweb_download_callback.h"
#include "ohos_nweb/include/ark_web_download_callback.h"

namespace OHOS::ArkWeb {

class ArkWebDownloadCallbackWrapper : public OHOS::NWeb::NWebDownloadCallback {
public:
    ArkWebDownloadCallbackWrapper(ArkWebRefPtr<ArkWebDownloadCallback> ark_web_download_callback);
    ~ArkWebDownloadCallbackWrapper() = default;

    /**
     * @brief Notify the host application that a file should be downloaded
     *
     * @param url The full url to the content that should be downloaded.
     * @param user_agent The user agent to be used for the download.
     * @param content_disposition Content-Disposition http header, if present.
     * @param mime_type The mimetype of the content reported by the server.
     * @param content_length The file size reported by the server.
     */
    void OnDownloadStart(const std::string& url, const std::string& user_agent, const std::string& content_disposition,
        const std::string& mime_type, long content_length) override;

private:
    ArkWebRefPtr<ArkWebDownloadCallback> ark_web_download_callback_;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_DOWNLOAD_CALLBACK_WRAPPER_H_