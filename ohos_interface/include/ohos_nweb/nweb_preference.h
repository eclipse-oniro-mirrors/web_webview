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

    enum class CopyOptionMode { NONE = 0, IN_APP = 1, LOCAL_DEVICE = 2, CROSS_DEVICE = 3 };

    /* synchronous set NWebPreference and web preferences */
    /**
     * Enables or disables content URL(content from a content provider installed
     * in the system) access within WebView. The default is true.
     */
    virtual void PutEnableContentAccess(bool flag) = 0;

    /**
     * Enables or disables file system access within WebView. But files in the
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
     * Put whether to block the WebView from loading image resources from the
     * network (http and https URI schemes). This settings is invalid, if {@link
     * #IsImageLoadingAllowed} returns false. The default is false.
     */
    virtual void PutLoadImageFromNetworkDisabled(bool flag) = 0;

    /**
     * Put the cursive font family name. The default is "cursive".
     *
     * @param font a font family name
     */
    virtual void PutCursiveFontFamilyName(const std::string& font) = 0;

    /**
     * Enables or disables the database storage API. The default is false.
     * This setting is global and effectd all WebView instances in a
     * process. You must modify this before loading any webView page so that the
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
    virtual void PutDefaultTextEncodingFormat(const std::string& encoding) = 0;

    /**
     * Enables or disables the DOM storage API. The default value is false.
     */
    virtual void PutDomStorageEnabled(bool flag) = 0;

    /**
     * Put the fantasy font family name. The default is "fantasy".
     *
     * @param font a font family name
     */
    virtual void PutFantasyFontFamilyName(const std::string& font) = 0;

    /**
     * Put the fixed font family name. The default is "monospace".
     *
     * @param font a font family name
     */
    virtual void PutFixedFontFamilyName(const std::string& font) = 0;

    /**
     * Enables or disables the force dark mode for this NWeb.
     *
     * @param forceDark True if set the force dark mode enabled for this NWeb.
     */
    virtual void PutForceDarkModeEnabled(int forceDark) = 0;

    /**
     * Put whether JavaScript can open windows by JavaScript. This applies to the
     * JavaScript function {@code window.open()}. The default is false.
     */
    virtual void PutIsCreateWindowsByJavaScriptAllowed(bool flag) = 0;

    /**
     * Put whether the WebView can execute JavaScript. The default is false.
     */
    virtual void PutJavaScriptEnabled(bool flag) = 0;

    /**
     * Put whether the WebView can load image. The default is true.
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
     * Sets whether the WebView loads pages in overview mode, that is, zooms out the
     * content to fit on screen by width.
     *
     */
    virtual void PutLoadWithOverviewMode(bool flag) = 0;

    /**
     * Put the sans-serif font family name. The default is "sans-serif".
     *
     * @param font a font family name
     */
    virtual void PutSansSerifFontFamilyName(const std::string& font) = 0;

    /**
     * Put the serif font family name. The default is "serif".
     *
     * @param font a font family name
     */
    virtual void PutSerifFontFamilyName(const std::string& font) = 0;

    /**
     * Put the standard font family name. The default is "sans-serif".
     *
     * @param font a font family name
     */
    virtual void PutStandardFontFamilyName(const std::string& font) = 0;

    /**
     * Put the user-agent string to the nweb. If it is null or empty,
     * webview will use the system default value. Changing the user-agent
     * while loading a web page will cause the web page to reload.
     *
     * @param ua user-agent string. The value may be null.
     */
    virtual void PutUserAgent(const std::string& ua) = 0;

    /**
     * Put the zoom percentage of the page text. The default is 100.
     *
     * @param textZoom the zoom percentage of the page text
     */
    virtual void PutZoomingForTextFactor(int textZoom) = 0;

    /**
     * Put whether the WebView can get geolocation. The default is true.
     * To get geolocation, an application must have permission to access
     * the device location, see ohos.permission.LOCATION and
     * ohos.permission.LOCATION_IN_BACKGROUND and implement the
     * NWebHandler#OnGeolocationShow callback to receive notifications of
     * the location request via the JavaScript Geolocation API.
     */
    virtual void PutGeolocationAllowed(bool flag) = 0;

    /**
     * Put the WebView's behavior when a secure origin attempts to load a
     * resource from an insecure origin. The default is NEVER_ALLOW.
     *
     * @param mode The mixed content mode to use.
     */
    virtual void PutAccessModeForSecureOriginLoadFromInsecure(AccessMode mode) = 0;

    /**
     * Put whether the WebView supports zooming. The default is true.
     */
    virtual void PutZoomingFunctionEnabled(bool flag) = 0;

    /**
     * Put whether the WebView block loading resources from the network. The
     * default value is false if the hap has the
     * ohos.permission.INTERNET permission, otherwise it is true.If the
     * hap does not have the ohos.permission.INTERNET permission,
     * attempts to set a value of false will be failed.
     */
    virtual void PutBlockNetwork(bool flag) = 0;

    enum CacheModeFlag { USE_DEFAULT = 0, USE_CACHE_ELSE_NETWORK, USE_NO_CACHE, USE_CACHE_ONLY };
    /**
     * PutCacheMode
     */
    virtual void PutCacheMode(CacheModeFlag flag) = 0;

    /**
     * Put whether the NWeb can be debugging, default value is false.
     */
    virtual void PutWebDebuggingAccess(bool flag) = 0;

    /**
     * Put whether media playback needs to be triggered by user gestures, default value is false.
     */
    virtual void PutMediaPlayGestureAccess(bool flag) = 0;

    /**
     * Put whether smooth mode is supported.
     */
    virtual void PutPinchSmoothMode(bool flag) = 0;

    /**
     * Put whether support multi window, default value is false.
     */
    virtual void PutMultiWindowAccess(bool flag) = 0;

    /* get methods */
    /**
     * Get if content URL(content from a content provider installed
     * in the system) access within WebView is supported.
     *
     * @see PutEnableContentAccess
     */
    virtual bool EnableContentAccess() = 0;

    /**
     * Get if file system access within WebView is supported. Notified files in the
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
     * Get if the WebView from loading image resources from the
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
     * An instance of WebView could use a different User-Agent that
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
     * Get whether the force dark mode is enabled for this NWeb.
     *
     * @see PutForceDarkModeEnabled
     */
    virtual int ForceDarkModeEnabled() = 0;

    /**
     * Get if JavaScript can open windows.
     *
     * @see PutIsCreateWindowsByJavaScriptAllowed
     */
    virtual bool IsCreateWindowsByJavaScriptAllowed() = 0;

    /**
     * Get if the WebView can execute JavaScript.
     *
     * @see PutJavaScriptEnabled
     */
    virtual bool IsJavaScriptAllowed() = 0;

    /**
     * Get if the WebView can load image.
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
     * Get the swith for the overview mode.
     *
     * @see PutLoadWithOverviewMode
     */
    virtual bool IsLoadWithOverviewMode() = 0;

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
     * Get if the WebView can get geolocation.
     *
     * @see PutGeolocationAllowed
     */
    virtual bool GeolocationAllowed() = 0;

    /**
     * Get the WebView's behavior when a secure origin attempts to load a
     * resource from an insecure origin.
     *
     * @see PutAccessModeForSecureOriginLoadFromInsecure
     */
    virtual AccessMode AccessModeForSecureOriginLoadFromInsecure() = 0;

    /**
     * Get if the WebView supports zooming.
     *
     * @see PutZoomingFunctionEnabled
     */
    virtual bool ZoomingfunctionEnabled() = 0;

    /**
     * Get if the WebView block loading resources from the network.
     *
     * @see PutBlockNetwork
     */
    virtual bool IsNetworkBlocked() = 0;

    /**
     * Get cache mode
     *
     * @see PutCacheMode
     */
    virtual CacheModeFlag CacheMode() = 0;

    /**
     * Get if the NWeb can be debugging.
     *
     * @see PutWebDebuggingAccess
     */
    virtual bool IsWebDebuggingAccess() = 0;

    /**
     * Get whether media playback needs to be triggered by user gestures.
     *
     * @see PutMediaPlayGestureAccess
     */
    virtual bool GetMediaPlayGestureAccess() = 0;

    /**
     * Get whether smooth mode is supported.
     */
    virtual bool GetPinchSmoothMode() = 0;

    /**
     * Get whether support multi window.
     *
     * @see PutMultiWindowAccess
     */
    virtual bool IsMultiWindowAccess() = 0;

    /**
     * Enables or disables the dark mode prefer-color-scheme for this NWeb.
     *
     * @param darkScheme True if set the dark mode prefer-color-scheme enabled for this NWeb.
     */
    virtual void PutDarkSchemeEnabled(int darkScheme) = 0;

    /**
     * Get whether the dark mode prefer-color-scheme is enabled for this NWeb.
     *
     * @see PutDarkSchemeEnabled
     */
    virtual int DarkSchemeEnabled() = 0;

    /**
     * Get whether enable horizontal scroll bar.
     *
     * @see PutHorizontalScrollBarAccess
     */
    virtual bool IsHorizontalScrollBarAccess() = 0;

    /**
     * Get whether enable vertical scroll bar.
     *
     * @see PutVerticalScrollBarAccess
     */
    virtual bool IsVerticalScrollBarAccess() = 0;

    /**
     * Put whether enable horizontal scroll bar, default value is false.
     */
    virtual void PutHorizontalScrollBarAccess(bool flag) = 0;

    /**
     * Put whether enable vertical scroll bar, default value is false.
     */
    virtual void PutVerticalScrollBarAccess(bool flag) = 0;

    /**
     * Get the color of scrollbar.
     *
     * @see PutScrollbarColor
     */
    virtual uint32_t GetScrollBarColor() = 0;

    /**
     * Put the UX color of scrollbar.
     */
    virtual void PutScrollBarColor(uint32_t colorValue) = 0;

    /**
     * Get over-scroll Mode.
     *
     * @see PutScrollbarColor
     */
    virtual int GetOverscrollMode() = 0;

    /**
     * Put over-scroll Mode.
     */
    virtual void PutOverscrollMode(int overScrollMode) = 0;

    /**
     * Put copy-option.
     */
    virtual void PutCopyOptionMode(CopyOptionMode copyOption) = 0;

    /**
     * Get copy-option Mode.
     *
     * @see PutCopyOptionMode
     */
    virtual CopyOptionMode GetCopyOptionMode() = 0;

    /**
     * Put whether the embed mode. The default is false.
     */
    virtual void SetNativeEmbedMode(bool flag) = 0;

    /**
     * Get whether the embed mode. The default is false.
     */
    virtual bool GetNativeEmbedMode() = 0;

    /**
     * Register native embed rule. The default pattern is ["embed", "native/"].
     */
    virtual void RegisterNativeEmbedRule(const std::string&, const std::string&) = 0;

    /**
     * Set whether the scroll is enabled.
     */
    virtual void SetScrollable(bool enable) = 0;

    /**
     * Get whether the scroll is enabled.
     */
    virtual bool GetScrollable() = 0;

    /**
     * Put whether fonts are automatically laid out, default value is ture.
     */
    virtual void PutTextAutosizingEnabled(bool flag) = 0;

    /**
     * Set whether to support the viewport attribute of the meta tag in the
     * frontend page.
     */
    virtual void SetViewportEnable(bool enable) = 0;

    /**
     * Set native video player config.
     * @param enable Enable native video player or not.
     * @param shouldOverlay Native video player should overlay web page or not.
     */
    virtual void SetNativeVideoPlayerConfig(bool enable, bool shouldOverlay) = 0;

    /**
     * Get surfaceId.
     */
    virtual std::string GetSurfaceId() { return ""; }

    /**
     * Set surfaceId.
     */
    virtual void SetSurfaceId(const std::string& surfaceId) {}

    /**
     * Set whether the scrollbar is displayed.
     */
    virtual void PutOverlayScrollbarEnabled(bool enable) {}

    /**
     * Set whether the scroll is enabled.
     */
    virtual void SetScrollable(bool enable, int32_t scrollType) {}

    /**
     * Set whether to support the blur when the keyboard is hidden by manual.
     * @param enable set whether blur is allowed.
     */
    virtual void SetBlurOnKeyboardHideMode(int enable) {}

    /**
     * Set whether to connect to media avsession.
     */
    virtual void PutWebMediaAVSessionEnabled(bool enable) {}

    /**
     * Set the scale of the font-weight.The default is 1.0f.
     */
    virtual void SetFontWeightScale(float scale) {}

    /**
     * Set whether to use the intrinsic size. The default is false.
     */
    virtual void SetIntrinsicSizeEnable(bool enable) {}

    /**
     * Set whether to support css diplay when reporting the visibility of native embed.
     * The default is false.
     */
    virtual void SetCssDisplayChangeEnabled(bool enable) {}

    /**
     * Set whether to bypass vsync.
     * The default is none.
     */
    virtual void SetBypassVsyncCondition(int32_t condition) {}

    /**
     * Set the gesture focus mode.
     */
    virtual void SetGestureFocusMode(int32_t mode) {}
};

} // namespace OHOS::NWeb

#endif // NWEB_PREFERENCE_H
