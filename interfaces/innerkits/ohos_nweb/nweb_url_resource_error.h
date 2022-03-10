// Copyright (c) 2022 Huawei Device Co., Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NWEB_URL_RESOURCE_ERROR_H
#define NWEB_URL_RESOURCE_ERROR_H

#include <string>

#include "nweb_export.h"
namespace OHOS::NWeb {
class OHOS_NWEB_EXPORT NWebUrlResourceError {
public:
    NWebUrlResourceError() = default;

    virtual ~NWebUrlResourceError() = default;

    /**
     * @brief Gets the error description.
     *
     * @brief Gets the ErrorInfo.
     *
     * @return The description of the error.
     */
    virtual const std::string &ErrorInfo() const = 0;

    /**
     * @brief Get the Error Code.
     *
     * @return The error code.
     */
    virtual int ErrorCode() const = 0;
};
}

#endif // NWEB_URL_RESOURCE_ERROR_H