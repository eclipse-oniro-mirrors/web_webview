// Copyright (c) 2022 Huawei Device Co., Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NWEB_JS_SSL_ERROR_RESULT_H
#define NWEB_JS_SSL_ERROR_RESULT_H

#include <string>
#include "nweb_export.h"

namespace OHOS::NWeb {
class OHOS_NWEB_EXPORT NWebJSSslErrorResult {
public:
    virtual ~NWebJSSslErrorResult() = default;

    /**
     * @brief Handle a confirmation response from the user, the url request will be continued.
     */
    virtual void HandleConfirm() = 0;

    /**
     * @brief Handle the result if the user cancelled the url request.
     */
    virtual void HandleCancel() = 0;
};
}

#endif