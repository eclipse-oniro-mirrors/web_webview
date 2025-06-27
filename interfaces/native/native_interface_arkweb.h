/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

/**
 * @addtogroup Web
 * @{
 *
 * @brief Provides APIs to use javascript proxy and run javascirpt code.
 * @since 11
 */
/**
 * @file native_interface_arkweb.h
 *
 * @brief Declares the APIs to use javascript proxy and run javascirpt code.
 * @library libohweb.so
 * @syscap SystemCapability.Web.Webview.Core
 * @since 11
 */
#ifndef NATIVE_INTERFACE_ARKWEB_H
#define NATIVE_INTERFACE_ARKWEB_H

#include <cstdint>

#include "arkweb_error_code.h"
#include "arkweb_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
* @brief Defines the javascript callback of the web component.
*
* @since 11
*/
typedef void (*NativeArkWeb_OnJavaScriptCallback)(const char*);

/**
* @brief Defines the javascript proxy callback of the web component.
*
* @since 11
*/
typedef char* (*NativeArkWeb_OnJavaScriptProxyCallback)(const char** argv, int32_t argc);

/**
* @brief Defines the valid callback of the web component.
*
* @since 11
*/
typedef void (*NativeArkWeb_OnValidCallback)(const char*);

/**
* @brief Defines the destroy callback of the web component.
*
* @since 11
*/
typedef void (*NativeArkWeb_OnDestroyCallback)(const char*);

/**
 * @brief Defines the callback of save cookie.
 *
 * @since 20
 */
typedef void (*OH_ArkWeb_OnCookieSaveCallback)();

/**
 * @brief Defines the blankless info.
 *
 * @since 20
 */
 typedef struct {
    /** The errCode of the blankless. */
    ArkWeb_BlanklessErrorCode errCode;
    /** The estimated similarity of the history snapshots. */
    double similarity;
    /** The loadingTime of the history loading. */
    int32_t loadingTime;
} ArkWeb_BlanklessInfo;

/**
 * @brief Loads a piece of code and execute JS code in the context of the currently displayed page.
 *
 * @param webTag The name of the web component.
 * @param jsCode a piece of javascript code.
 * @param callback Callbacks execute JavaScript script results.
 *
 * @syscap SystemCapability.Web.Webview.Core
 * @since 11
 */
void OH_NativeArkWeb_RunJavaScript(const char* webTag, const char* jsCode, NativeArkWeb_OnJavaScriptCallback callback);

/**
 * @brief Registers the JavaScript object and method list.
 *
 * @param webTag The name of the web component.
 * @param objName The name of the registered object.
 * @param methodList The method of the application side JavaScript object participating in the registration.
 * @param callback The callback function registered by developer is called back when HTML side uses.
 * @param size The size of the callback.
 * @param needRefresh if web need refresh.
 *
 * @syscap SystemCapability.Web.Webview.Core
 * @since 11
 */
void OH_NativeArkWeb_RegisterJavaScriptProxy(const char* webTag, const char* objName, const char** methodList,
    NativeArkWeb_OnJavaScriptProxyCallback* callback, int32_t size, bool isNeedRefresh);

/**
 * @brief Deletes the registered object which th given name.
 *
 * @param webTag The name of the web component.
 * @param objName The name of the registered object.
 *
 * @syscap SystemCapability.Web.Webview.Core
 * @since 11
 */
void OH_NativeArkWeb_UnregisterJavaScriptProxy(const char* webTag, const char* objName);

/**
 * @brief Registers the valid callback.
 *
 * @param webTag The name of the web component.
 * @param callback The callback in which we can register object.
 *
 * @syscap SystemCapability.Web.Webview.Core
 * @since 11
 */
void OH_NativeArkWeb_SetJavaScriptProxyValidCallback(const char* webTag, NativeArkWeb_OnValidCallback callback);

/**
 * @brief Get the valid callback.
 *
 * @param webTag The name of the web component.
 * @return return the valid callback function registered.
 *
 * @syscap SystemCapability.Web.Webview.Core
 * @since 11
 */
NativeArkWeb_OnValidCallback OH_NativeArkWeb_GetJavaScriptProxyValidCallback(const char* webTag);

/**
 * @brief Registers the destroy callback.
 *
 * @param webTag The name of the web component.
 * @param callback the destroy callback.
 *
 * @syscap SystemCapability.Web.Webview.Core
 * @since 11
 */
void OH_NativeArkWeb_SetDestroyCallback(const char* webTag, NativeArkWeb_OnDestroyCallback callback);

/**
 * @brief Get the destroy callback.
 *
 * @param webTag The name of the web component.
 * @return return the destroy callback function registered.
 *
 * @syscap SystemCapability.Web.Webview.Core
 * @since 11
 */
NativeArkWeb_OnDestroyCallback OH_NativeArkWeb_GetDestroyCallback(const char* webTag);

/**
 * @brief Loads the data or URL.
 *        This function should be called on main thread.
 *
 * @param webTag The name of the web component.
 * @param data A string encoded according to "Base64" or "URL", should not be NULL.
 * @param mimeType Media type. For example: "text/html", should not be NULL.
 * @param encoding Encoding type. For example: "UTF-8", should not be NULL.
 * @param baseUrl A specified URL path ("http"/"https"/"data" protocol),
 *                which is assigned to window.origin by the Web component.
 * @param historyUrl History URL. When it is not empty, it can be managed by
 *                   history records to realize the back and forth function.
 * @return LoadData result code.
 *         {@link ARKWEB_SUCCESS} load data success.
 *         {@link ARKWEB_INVALID_PARAM} Mandatory parameters are left unspecified or
 *                                      Incorrect parameter types or Parameter verification failed.
 *         {@link ARKWEB_INIT_ERROR} Initialization error, can't get a valid Web for the webTag.
 *         {@link ARKWEB_LIBRARY_OPEN_FAILURE} Failed to open the library.
 *         {@link ARKWEB_LIBRARY_SYMBOL_NOT_FOUND} The required symbol was not found in the library.
 *
 * @syscap SystemCapability.Web.Webview.Core
 * @since 15
 */
ArkWeb_ErrorCode OH_NativeArkWeb_LoadData(const char* webTag,
                                          const char* data,
                                          const char* mimeType,
                                          const char* encoding,
                                          const char* baseUrl,
                                          const char* historyUrl);

/**
 * @brief Registers a JavaScript object with callback methods, which may return values. This object will be injected
 *        into all frames of the current page, including all iframes, and will be accessible using the specified
 *        name in ArkWeb_ProxyObjectWithResult. The object will only be available in JavaScript after the next
 *        load or reload.
 *        These methods will be executed in the ArkWeb worker thread.
 *
 * @param webTag Name of the web component.
 * @param proxyObject JavaScript object to register, the object has callback functions with return value.
 * @param permission Optional JSON string(default is null) for JSBridge permission control,
 *                   allowing URL whitelist configuration at object-level and method-level.
 * @syscap SystemCapability.Web.Webview.Core
 * @since 20
 */
void OH_NativeArkWeb_RegisterAsyncThreadJavaScriptProxy(const char* webTag,
    const ArkWeb_ProxyObjectWithResult* proxyObject, const char* permission);

/**
 * @brief get the white screen optimization info when the current page is loaded.
 *
 * @param webTag The name of the web component.
 * @param key A key string of the loading page, should not be NULL.
 * @return Blankless info.
 *
 * @since 20
 */
ArkWeb_BlanklessInfo OH_NativeArkWeb_GetBlanklessInfoWithKey(const char* webTag, const char* key);

/**
 * @brief set the white screen optimization solution when the current page is loaded.
 *
 * @param webTag The name of the web component.
 * @param key A key string of the loading page, should not be NULL.
 * @param isStarted If enabled blankless.
 * @return Blankless result code.
 *
 * @since 20
 */
ArkWeb_BlanklessErrorCode OH_NativeArkWeb_SetBlanklessLoadingWithKey(const char* webTag,
                                                                     const char* key,
                                                                     bool isStarted);

/**
 * @brief The apps can use this interface to clear the page cache. The "Clear Page"
 * here is within the page range set in the API getBlanklessInfoWithKey.
 *
 * @param key A array of key string.
 * @param size The number of elements in the key array.
 *
 * @since 20
 */
void OH_NativeArkWeb_ClearBlanklessLoadingCache(const char* key[], uint32_t size);

/**
 * @brief Set the capacity of the blankless cache.
 *
 * @param capacity The blankless capacity the apps want to set.
 * @return The real blankless capacity, 0-100.
 *
 * @since 20
 */
uint32_t OH_NativeArkWeb_SetBlanklessLoadingCacheCapacity(uint32_t capacity);

/**
 * @brief Ensure that all cookies currently accessible via the CookieManager API have been persisted to disk.
 *        If you want to use this interface in a non-UI thread, you need to initialize the CookieManager interface
 *        using OH_ArkWeb_GetNativeAPI first.
 * @return Save cookie result code.
 *         {@link ARKWEB_SUCCESS} save cookie success.
 *         {@link ARKWEB_COOKIE_MANAGER_NOT_INITIALIZED} It is not allowed to call on a non-UI thread without
 *                                                       initializing the CookieManager interface. please
 *   													 initialize the CookieManager interface using
 *  													 OH_ArkWeb_GetNativeAPI first.
 * @since 20
 */
ArkWeb_ErrorCode OH_ArkWebCookieManager_SaveCookieSync();

/**
 * @brief Ensure that all cookies currently accessible via the CookieManager API have been persisted to disk.
 *        Without initializing the CookieManager interface, this call will automatically be executed on the UI thread.
 *        If you want to use this interface in a non-UI thread, you need to initialize the CookieManager interface
 *        using OH_ArkWeb_GetNativeAPI first.
 * @param callback Callback execute when save cookie done.
 * @since 20
 */
void OH_ArkWebCookieManager_SaveCookieAsync(OH_ArkWeb_OnCookieSaveCallback callback);

#ifdef __cplusplus
};
#endif
#endif // NATIVE_INTERFACE_ARKWEB_H
