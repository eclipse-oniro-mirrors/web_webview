// Copyright (c) 2022 Huawei Device Co., Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "nweb_downloadlistener_impl_test.h"

#include <iostream>
#include "nweb_test_log.h"

namespace OHOS::NWeb {
void NWebDownloadListenerImplTest::OnDownloadStart(const std::string &url, const std::string &userAgent,
                                                   const std::string &contentDisposition,
                                                   const std::string &mimetype,
                                                   long contentLength)
{
    TESTLOG_I("NWebDownloadListenerImplTest::onDownloadStart");
    TESTLOG_I("url=%{public}s", url.c_str());
    TESTLOG_I("userAgent=%{public}s", userAgent.c_str());
    TESTLOG_I("contentDisposition=%{public}s", contentDisposition.c_str());
    TESTLOG_I("mimetype=%{public}s", mimetype.c_str());
    TESTLOG_I("contentLength=%{public}ld", contentLength);
}
} // namespace OHOS::NWeb