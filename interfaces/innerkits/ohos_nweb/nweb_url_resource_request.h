// Copyright (c) 2022 Huawei Device Co., Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef NWEB_URL_RESOURCE_REQUEST_H
#define NWEB_URL_RESOURCE_REQUEST_H
#include <map>
#include <string>

#include "nweb_export.h"

namespace OHOS::NWeb {
class OHOS_NWEB_EXPORT NWebUrlResourceRequest {
public:
    NWebUrlResourceRequest() = default;

    virtual ~NWebUrlResourceRequest() = default;

    /**
     * @brief Gets the method associated with the request, for example "GET".
     *
     * @retval method the method associated with the request.
     */
    virtual const std::string &Method() = 0;

    /**
     * @brief  Gets the headers associated with the request.
     *
     * @retval the headers associated with the request.
     */
    virtual const std::map<std::string, std::string> &RequestHeaders() = 0;

    /**
     * @brief Gets the URL for which the resource request was made.
     *
     * @retval URL url string
     */
    virtual const std::string &Url() = 0;

    /**
     * @brief Gets whether a gesture (such as a click) was associated with the
     * request.
     *
     * @retval gesture
     */
    virtual bool FromGesture() = 0;

    /**
     * @brief Gets whether the request was made in order to fetch the main frame's
     * document.
     *
     * @retval Is main frame
     */
    virtual bool IsAboutMainFrame() = 0;

    /**
     * @brief Gets whether the request was a result of a server-side redirect.
     *
     * @retval is redirect
     */
    virtual bool IsRequestRedirect() = 0;
};
}

#endif