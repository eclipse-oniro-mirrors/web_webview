// Copyright (c) 2022 Huawei Device Co., Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NWEB_DOWNLOAD_CALLBACK_H
#define NWEB_DOWNLOAD_CALLBACK_H

#include <string>

#include "nweb_export.h"

namespace OHOS::NWeb {
class OHOS_NWEB_EXPORT NWebDownloadCallback {
public:
    NWebDownloadCallback() = default;

    virtual ~NWebDownloadCallback() = default;
    /**
     * @brief Notify the host application that a file should be downloaded
     *
     * @param url The full url to the content that should be downloaded.
     * @param userAgent The user agent to be used for the download.
     * @param contentDisposition Content-disposition http header, if present.
     * @param mimetype The mimetype of the content reported by the server.
     * @param contentLength The file size reported by the server.
     */
    virtual void OnDownloadStart(const std::string& url,
                                 const std::string& userAgent,
                                 const std::string& contentDisposition,
                                 const std::string& mimetype,
                                 long contentLength) = 0;
};
}  // namespace OHOS::NWeb

#endif  // NWEB_DOWNLOAD_CALLBACK_H