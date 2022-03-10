// Copyright (c) 2022 Huawei Device Co., Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NWEB_HANDLER_IMPL_TEST_FOR_INTERCEPT_H
#define NWEB_HANDLER_IMPL_TEST_FOR_INTERCEPT_H

#include "nweb_handler.h"

namespace OHOS::NWeb {
class NWebHandlerImplTestForIntercept : public NWebHandler {
public:
    NWebHandlerImplTestForIntercept() = default;
    ~NWebHandlerImplTestForIntercept() = default;
    void SetNWeb(std::shared_ptr<NWeb> nweb) override;
    std::shared_ptr<NWebUrlResourceResponse> OnHandleInterceptRequest(
        std::shared_ptr<NWebUrlResourceRequest> request) override;
private:
    std::weak_ptr<NWeb> nwebweak_;
};
} // namespace OHOS::NWeb

#endif // NWEB_HANDLER_IMPL_TEST_FOR_INTERCEPT_H