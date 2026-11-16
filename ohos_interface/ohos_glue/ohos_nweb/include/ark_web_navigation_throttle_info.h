/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef ARK_WEB_NAVIGATION_THROTTLE_INFO_H_
#define ARK_WEB_NAVIGATION_THROTTLE_INFO_H_
#pragma once

#include "base/include/ark_web_base_ref_counted.h"
#include "base/include/ark_web_types.h"

namespace OHOS::ArkWeb {

/**
 * @brief Encapsulates the navigation information passed to a navigation throttle callback.
 *
 * Field availability varies by stage: status code, mime type, and content disposition are valid
 * only for WILL_REDIRECT_REQUEST and WILL_PROCESS_RESPONSE; error code and error description are
 * valid only for WILL_FAIL_REQUEST. Inapplicable fields keep their default values.
 */
/*--ark web(source=webcore)--*/
class ArkWebNavigationThrottleInfo : public virtual ArkWebBaseRefCounted {
public:
    /**
     * @brief Get the url of the navigation.
     *
     * @return The url of the navigation.
     */
    /*--ark web()--*/
    virtual ArkWebString GetUrl() = 0;

    /**
     * @brief Whether the navigation targets the main frame.
     *
     * @return True if the navigation targets the main frame.
     */
    /*--ark web()--*/
    virtual bool IsMainFrame() = 0;

    /**
     * @brief Whether the navigation was initiated by a user gesture.
     *
     * @return True if the navigation was initiated by a user gesture.
     */
    /*--ark web()--*/
    virtual bool HasUserGesture() = 0;

    /**
     * @brief Whether the navigation was initiated by the renderer.
     *
     * @return True if the navigation was initiated by the renderer.
     */
    /*--ark web()--*/
    virtual bool IsRendererInitiated() = 0;

    /**
     * @brief Whether the navigation is a redirect (server-side or client-side).
     *
     * @return True if the navigation is a redirect.
     */
    /*--ark web()--*/
    virtual bool IsRedirect() = 0;

    /**
     * @brief Get the page transition value.
     *
     * First valid in WILL_START_REQUEST; may be updated in WILL_REDIRECT_REQUEST
     * and remains unchanged in subsequent stages.
     *
     * @return The page transition value.
     */
    /*--ark web()--*/
    virtual int32_t GetPageTransition() = 0;

    /**
     * @brief Get the HTTP request method of the navigation request.
     *
     * First valid in WILL_START_REQUEST; may be updated in WILL_REDIRECT_REQUEST
     * and remains unchanged in subsequent stages.
     *
     * @return The HTTP request method (e.g. "GET", "POST").
     */
    /*--ark web()--*/
    virtual ArkWebString GetRequestMethod() = 0;

    /**
     * @brief Get the HTTP status code.
     *
     * Valid for WILL_REDIRECT_REQUEST and WILL_PROCESS_RESPONSE.
     *
     * @return The HTTP status code.
     */
    /*--ark web()--*/
    virtual int32_t GetStatusCode() = 0;

    /**
     * @brief Get the MIME type of the response.
     *
     * Valid for WILL_PROCESS_RESPONSE.
     *
     * @return The MIME type of the response.
     */
    /*--ark web()--*/
    virtual ArkWebString GetMimeType() = 0;

    /**
     * @brief Get the Content-Disposition header of the response.
     *
     * Valid for WILL_PROCESS_RESPONSE.
     *
     * @return The Content-Disposition header of the response.
     */
    /*--ark web()--*/
    virtual ArkWebString GetContentDisposition() = 0;

    /**
     * @brief Get the network error code.
     *
     * Valid for WILL_FAIL_REQUEST.
     *
     * @return The network error code.
     */
    /*--ark web()--*/
    virtual int32_t GetErrorCode() = 0;

    /**
     * @brief Get the description of the network error.
     *
     * Valid for WILL_FAIL_REQUEST.
     *
     * @return The description of the network error.
     */
    /*--ark web()--*/
    virtual ArkWebString GetErrorDescription() = 0;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_NAVIGATION_THROTTLE_INFO_H_
