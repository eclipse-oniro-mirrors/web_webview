/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef NWEB_COOKIE_MANAGER_H
#define NWEB_COOKIE_MANAGER_H

#include <memory>
#include <string>

#include "nweb_export.h"
#include "nweb_value_callback.h"

namespace OHOS::NWeb {

class OHOS_NWEB_EXPORT NWebCookieManager {
public:
    NWebCookieManager() = default;

    virtual ~NWebCookieManager() = default;

    /**
     * @brief Get whether the instance can send and accept cookies.
     *
     * @return true if the instance send and accept cookies.
     */
    virtual bool IsAcceptCookieAllowed() = 0;

    /**
     * @brief Sets whether the instance should send and accept cookies.
     * By default this is set to be true and the nweb accepts cookies.
     *
     * @param accept whether the instance should send and accept cookies.
     */
    virtual void PutAcceptCookieEnabled(bool accept) = 0;

    /**
     * @brief Get whether the instance allows setting cookies of third parties
     *
     * @return true if the instance allows the setting of third-party cookies.
     */
    virtual bool IsThirdPartyCookieAllowed() = 0;

    /**
     * @brief Set whether the instance allows setting cookies of third parties.
     * By default, this value is set to be false. Nweb does not allow the setting of third-party cookies.
     *
     * @param accept whether the instance allows the setting of third-party cookies.
     */
    virtual void PutAcceptThirdPartyCookieEnabled(bool accept) = 0;

    /**
     * @brief Get whether instances can send and accept cookies for file scheme URLs.
     *
     * @return true if instances send and accept cookies for file scheme URLs.
     */
    virtual bool IsFileURLSchemeCookiesAllowed() = 0;

    /**
     * @brief Sets whether the instance should send and accept cookies for file scheme URLs.
     *
     * @param allow whether the instance should send and accept cookies for file scheme URLs.
     */
    virtual void PutAcceptFileURLSchemeCookiesEnabled(bool allow) = 0;

    /**
     * @brief Gets all the cookies for the given URL.
     *
     * @param url the URL for which the cookies are requested.
     * @param callback a callback which is executed when the cookies have been gotten.
     */
    virtual void ReturnCookie(const std::string& url, std::shared_ptr<NWebStringValueCallback> callback) = 0;

    /**
     * @brief Gets all the cookies for the given URL. This is sync method
     *
     * @param url the URL for which the cookies are requested.
     * @param value the cookie as a string, using the format of the 'Set-Cookie' HTTP response header.
     * @param incognito_mode true if web is in the incognito mode, false otherwise.
     * @return the cookie value for given URL.
     */
    virtual std::string ReturnCookie(const std::string& url, bool& is_valid, bool incognito_mode) = 0;

    /**
     * @brief Sets a single cookie (key-value pair) for the given URL.
     *
     * @param url the URL for which the cookie is to be set.
     * @param value the cookie as a string, using the format of the 'Set-Cookie' HTTP response header.
     * @param callback a callback to be executed when the cookie has been set.
     */
    virtual void SetCookie(
        const std::string& url, const std::string& value, std::shared_ptr<NWebBoolValueCallback> callback) = 0;

    /**
     * @brief Sets a single cookie (key-value pair) for the given URL sync.
     *
     * @param url the URL for which the cookie is to be set.
     * @param value the cookie as a string, using the format of the 'Set-Cookie' HTTP response header.
     * @param incognito_mode true if web is in the incognito mode, false otherwise.
     * @return 0 if set cookie success else return error id.
     */
    virtual int SetCookie(const std::string& url, const std::string& value, bool incognito_mode) = 0;

    /**
     * @brief Gets whether there are stored cookies.
     *
     * @param callback a callback to be executed when the cookie has checked.
     */
    virtual void ExistCookies(std::shared_ptr<NWebBoolValueCallback> callback) = 0;

    /**
     * @brief Gets whether there are stored cookies.
     *
     * @param incognito_mode true if web is in the incognito mode, false otherwise.
     * @return true if there are stored cookies else false.
     */
    virtual bool ExistCookies(bool incognito_mode) = 0;

    /**
     * @brief Ensures all cookies currently accessible through the ReturnCookie API are written to
     * persistent storage.
     *
     * @param callback a callback to be executed when cookies has Stored.
     */
    virtual void Store(std::shared_ptr<NWebBoolValueCallback> callback) = 0;

    /**
     * @brief Ensures all cookies currently accessible through the ReturnCookie API are written to
     * persistent storage.
     *
     * @param true if store cookie success else return false.
     */
    virtual bool Store() = 0;

    /**
     * @brief Removes all session cookies, which are cookies without an expiration date.
     *
     * @param callback a callback to be executed when all session cookies has removed.
     */
    virtual void DeleteSessionCookies(std::shared_ptr<NWebBoolValueCallback> callback) = 0;

    /**
     * @brief Removes all cookies.
     *
     * @param callback a callback to be executed when all cookies has removed.
     * @param incognito_mode true if web is in the incognito mode, false otherwise.
     */
    virtual void DeleteCookieEntirely(std::shared_ptr<NWebBoolValueCallback> callback, bool incognito_mode) = 0;

    /**
     * @brief Configs a single cookie (key-value pair) for the given URL.
     *
     * @param url the URL for which the cookie is to be set.
     * @param value the cookie as a string, using the format of the 'Set-Cookie' HTTP response header.
     * @param callback a callback to be executed when the cookie has been set.
     */
    virtual void ConfigCookie(
        const std::string& url, const std::string& value, std::shared_ptr<NWebLongValueCallback> callback) = 0;
};

} // namespace OHOS::NWeb

#endif // NWebCookieManager
