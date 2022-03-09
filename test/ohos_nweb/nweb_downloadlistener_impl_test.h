// Copyright (c) 2022 Huawei Device Co., Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NWEB_DOWNLOADLISTENER_IMPL_TEST_H
#define NWEB_DOWNLOADLISTENER_IMPL_TEST_H

#include "nweb_download_callback.h"

namespace OHOS::NWeb {
class NWebDownloadListenerImplTest : public NWebDownloadCallback {
public:
    NWebDownloadListenerImplTest() = default;
    ~NWebDownloadListenerImplTest() = default;
    void OnDownloadStart(const std::string &url, const std::string &userAgent,
                         const std::string &contentDisposition,
                         const std::string &mimetype,
                         long contentLength) override;
};
} // namespace OHOS::NWeb

#endif // NWEB_DOWNLOADLISTENER_IMPL_TEST_H