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

#ifndef NWEB_PREFERENCE_H
#define NWEB_PREFERENCE_H

#include <string>
#include "nweb_export.h"

namespace OHOS::NWeb {
class OHOS_NWEB_EXPORT NWebPreference {
public:
    NWebPreference() = default;
    virtual ~NWebPreference() = default;

    enum class AccessMode { ALWAYS_ALLOW = 0, NEVER_ALLOW = 1, COMPATIBILITY_MODE = 2 };

    /* Synchronously set NWebPreference and web preferences */
    /**
     * Enable or disable content URL(content from a content provider installed
     * in the system) access within NWeb. The default is true.
     */
    virtual void PutEnableContentAccess(bool flag) = 0;

    /**
     * Enable or disable file system access within NWeb. But files in the
     * path of AppData are still accessible. The default is false.
     */
    virtual void PutEnableRawFileAccess(bool flag) = 0;

    /**
     * Put whether to allow JavaScript running in a file scheme URL to access
     * content from other file scheme URLs. The default is false.
     */
    virtual void PutEnableRawFileAccessFromFileURLs(bool flag) = 0;

    /**
     * Put whether to allow JavaScript running in a file scheme URL to access
     * content from any origin. This includes access to content from other file
     * scheme URLs. See {@link #PutEnableRawFileAccessFromFileURLs}. The default is
     * false.
     */
    virtual void PutEnableUniversalAccessFromFileURLs(bool flag) = 0;

    /**
     * Put whether to block the NWeb from loading image resources from the
     * network (http and https URI schemes). This settings is invalid, if {@link
     * #IsImageLoadingAllowed} returns false. The default is false.
     */
    virtual void PutLoadImageFromNetworkDisabled(bool flag) = 0;

    /**
     * Put the cursive font family name. The default is "cursive".
     *
     * @param font a font family name
     */
    virtual void PutCursiveFontFamilyName(std::string font) = 0;

    /**
     * Enable or disable the database storage API. The default is false.
     * This setting is global and effectd all NWeb instances in a
     * process. You must modify this before loading any NWeb page so that the
     * changes won't be ignored.
     */
    virtual void PutDatabaseAllowed(bool flag) = 0;

    /**
     * Put the size of default fixed font. The default is 13.
     *
     * @param size A positive integer that ranges from 1 to 72. Any number outside
     *             the specified range will be pinned.
     */
    virtual void PutDefaultFixedFontSize(int size) = 0;

    /**
     * Put the size of default font. The default is 16.
     *
     * @param size A positive integer that ranges from 1 to 72. Any number outside
     *             the specified range will be pinned.
     */
    virtual void PutDefaultFontSize(int size) = 0;

    /**
     * Put the default text encoding format that uses to decode html pages.
     * The default is "UTF-8".
     *
     * @param the text encoding format
     */
    virtual void PutDefaultTextEncodingFormat(std::string encoding) = 0;

    /**
     * Enable or disable the DOM storage API. The default value is false.
     */
    virtual void PutDomStorageEnabled(bool flag) = 0;

    /**
     * Put the fantasy font family name. The default is "fantasy".
     *
     * @param font a font family name
     */
    virtual void PutFantasyFontFamilyName(std::string font) = 0;

    /**
     * Put the fixed font family name. The default is "monospace".
     *
     * @param font a font family name
     */
    virtual void PutFixedFontFamilyName(std::string font) = 0;

    /**
     * Enable or disable the force dark mode for this NWeb.
     *
     * @param forceDark true if set the force dark mode for this NWeb.
     */
    virtual void PutDarkModeEnabled(int forceDark) = 0;

    /**
     * Put whether JavaScript can open windows by JavaScript. This applies to the
     * JavaScript function {@code window.open()}. The default is false.
     */
    virtual void PutIsCreateWindowsByJavaScriptAllowed(bool flag) = 0;

    /**
     * Put whether the NWeb can execute JavaScript. The default is false.
     */
    virtual void PutJavaScriptEnabled(bool flag) = 0;

    /**
     * Put whether the NWeb can load image. The default is true.
     */
    virtual void PutImageLoadingAllowed(bool flag) = 0;

    /**
     * Put the lower limit of the minimum font size. The default is 8.
     *
     * @param size A positive integer that ranges from 1 to 72. Any number outside
     *             the specified range will be pinned.
     */
    virtual void PutFontSizeLowerLimit(int size) = 0;

    /**
     * Put the lower limit of the minimum logical font size. The default is 8.
     *
     * @param size A positive integer that ranges from 1 to 72. Any number outside
     *             the specified range will be pinned.
     */
    virtual void PutLogicalFontSizeLowerLimit(int size) = 0;

    /**
     * Put the sans-serif font family name. The default is "sans-serif".
     *
     * @param font a font family name
     */
    virtual void PutSansSerifFontFamilyName(std::string font) = 0;

    /**
     * Put the serif font family name. The default is "serif".
     *
     * @param font a font family name
     */
    virtual void PutSerifFontFamilyName(std::string font) = 0;

    /**
     * Put the standard font family name. The default is "sans-serif".
     *
     * @param font a font family name
     */
    virtual void PutStandardFontFamilyName(std::string font) = 0;

    /**
     * Put the user-agent string to the nweb. If it is null or empty,
     * NWeb will use the system default value. Changing the user-agent
     * while loading a web page will cause the web page to reload.
     *
     * @param ua user-agent string. The value may be null.
     */
    virtual void PutUserAgent(std::string ua) = 0;

    /**
     * Put the zoom percentage of the page text. The default is 100.
     *
     * @param textZoom the zoom percentage of the page text
     */
    virtual void PutZoomingForTextFactor(int textZoom) = 0;

    /**
     * Put whether the NWeb can get geolocation. The default is true.
     * To get geolocation, an application must have permission to access
     * the device location, see ohos.permission.LOCATION and
     * ohos.permission.LOCATION_IN_BACKGROUND and implement the
     * NWebHandler#OnGeolocationShow callback to receive notifications of
     * the location request via the JavaScript Geolocation API.
     */
    virtual void PutGeolocationAllowed(bool flag) = 0;

    /**
     * Put the NWeb's behavior when a secure origin attempts to load a
     * resource from an insecure origin. The default is NEVER_ALLOW.
     *
     * @param mode The mixed content mode to use.
     */
    virtual void PutAccessModeForSecureOriginLoadFromInsecure(
        AccessMode mode) = 0;

    /**
     * Put whether the NWeb supports zooming. The default is true.
     */
    virtual void PutZoomingFunctionEnabled(bool flag) = 0;

    /**
     * Put whether the NWeb block loading resources from the network. The
     * default value is false if the hap has the
     * ohos.permission.INTERNET permission, otherwise it is true.If the
     * hap does not have the ohos.permission.INTERNET permission,
     * attempts to set a value of false will be failed.
     */
    virtual void PutBlockNetwork(bool flag) = 0;

    /* get methods */
    /**
     * Get if content URL(content from a content provider installed
     * in the system) access within NWeb is supported.
     *
     * @see PutEnableContentAccess
     */
    virtual bool EnableContentAccess() = 0;

    /**
     * Get if file system access within NWeb is supported. Notified files in the
     * path of AppData are always accessible.
     *
     * @see PutEnableRawFileAccess
     */
    virtual bool EnableRawFileAccess() = 0;

    /**
     * Get if JavaScript running in a file scheme URL to access
     * content from other file scheme URLs is supported.
     *
     * @see PutEnableRawFileAccessFromFileURLs
     */
    virtual bool EnableRawFileAccessFromFileURLs() = 0;

    /**
     * Get if JavaScript running in a file scheme URL to access
     * content from any origin is supported. This includes access to content from other file
     * scheme URLs.
     *
     * @see PutEnableUniversalAccessFromFileURLs
     */
    virtual bool EnableUniversalAccessFromFileURLs() = 0;

    /**
     * Get if the NWeb from loading image resources from the
     * network (http and https URI schemes) is supported.
     *
     * @see PutLoadImageFromNetworkDisabled
     */
    virtual bool IsLoadImageFromNetworkDisabled() = 0;

    /**
     * Get the cursive font family name.
     *
     * @see PutCursiveFontFamilyName
     */
    virtual std::string CursiveFontFamilyName() = 0;

    /**
     * Get if the database storage API is supported.
     *
     * @see PutDatabaseAllowed
     */
    virtual bool IsDataBaseEnabled() = 0;

    /**
     * Get the size of default fixed font.
     *
     * @see PutDefaultFixedFontSize
     */
    virtual int DefaultFixedFontSize() = 0;

    /**
     * Get the size of default font.
     *
     * @see PutDefaultFontSize
     */
    virtual int DefaultFontSize() = 0;

    /**
     * Get the default text encoding format that uses to decode html pages.
     *
     * @see PutDefaultTextEncodingFormat
     */
    virtual std::string DefaultTextEncodingFormat() = 0;

    /**
     * Get the default user-agent string to the nweb.
     * An instance of NWeb could use a different User-Agent that
     * NWebPreference#PutUserAgent(String) set to.
     *
     * @see PutUserAgent
     */
    virtual std::string DefaultUserAgent() = 0;

    /**
     * Get if the DOM storage API is supported.
     *
     * @see PutDomStorageEnabled
     */
    virtual bool IsDomStorageEnabled() = 0;

    /**
     * Get the fantasy font family name.
     *
     * @see PutFantasyFontFamilyName
     */
    virtual std::string FantasyFontFamilyName() = 0;

    /**
     * Get the fixed font family name.
     *
     * @see PutFixedFontFamilyName
     */
    virtual std::string FixedFontFamilyName() = 0;

    /**
     * Get if the dark mode for this NWeb is supported.
     *
     * @see PutDarkModeEnabled
     */
    virtual int DarkModeEnabled() = 0;

    /**
     * Get if JavaScript can open windows.
     *
     * @see PutIsCreateWindowsByJavaScriptAllowed
     */
    virtual bool IsCreateWindowsByJavaScriptAllowed() = 0;

    /**
     * Get if the NWeb can execute JavaScript.
     *
     * @see PutJavaScriptEnabled
     */
    virtual bool IsJavaScriptAllowed() = 0;

    /**
     * Get if the NWeb can load image.
     *
     * @see PutImageLoadingAllowed
     */
    virtual bool IsImageLoadingAllowed() = 0;

    /**
     * Get the lower limit of the minimum font size.
     *
     * @see PutFontSizeLowerLimit
     */
    virtual int FontSizeLowerLimit() = 0;

    /**
     * Get the lower limit of the minimum logical font size.
     *
     * @see PutLogicalFontSizeLowerLimit
     */
    virtual int LogicalFontSizeLowerLimit() = 0;

    /**
     * Get the sans-serif font family name.
     *
     * @see PutSansSerifFontFamilyName
     */
    virtual std::string SansSerifFontFamilyName() = 0;

    /**
     * Get the serif font family name.
     *
     * @see PutSerifFontFamilyName
     */
    virtual std::string SerifFontFamilyName() = 0;

    /**
     * Get the standard font family name.
     *
     * @see PutStandardFontFamilyName
     */
    virtual std::string StandardFontFamilyName() = 0;

    /**
     * Get the user-agent string to the nweb.
     *
     * @see PutUserAgent
     */
    virtual std::string UserAgent() = 0;

    /**
     * Get the zoom percentage of the page text.
     *
     * @see PutZoomingForTextFactor
     */
    virtual int ZoomingForTextFactor() = 0;

    /**
     * Get if the NWeb can get geolocation.
     *
     * @see PutGeolocationAllowed
     */
    virtual bool GeolocationAllowed() = 0;

    /**
     * Get the NWeb's behavior when a secure origin attempts to load a
     * resource from an insecure origin.
     *
     * @see PutAccessModeForSecureOriginLoadFromInsecure
     */
    virtual AccessMode AccessModeForSecureOriginLoadFromInsecure() = 0;

    /**
     * Get if the NWeb supports zooming.
     *
     * @see PutZoomingFunctionEnabled
     */
    virtual bool ZoomingfunctionEnabled() = 0;

    /**
     * Get if the NWeb block loading resources from the network.
     *
     * @see PutBlockNetwork
     */
    virtual bool IsNetworkBlocked() = 0;
};
}  // namespace OHOS::NWeb

#endif  // NWEB_PREFERENCE_H
