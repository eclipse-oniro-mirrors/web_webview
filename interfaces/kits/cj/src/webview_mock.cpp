/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "cj_common_ffi.h"

extern "C" {
FFI_EXPORT int FfiOHOSWebviewCtlConstructor = 0;
FFI_EXPORT int FfiOHOSWebviewCtlConstructorWithWebTag = 0;
FFI_EXPORT int FfiOHOSWebviewCtlInitializeWebEngine = 0;
FFI_EXPORT int FfiOHOSWebviewCtlSetHttpDns = 0;
FFI_EXPORT int FfiOHOSWebviewCtlSetWebDebuggingAccess = 0;
FFI_EXPORT int FfiOHOSWebviewCtlLoadUrl = 0;
FFI_EXPORT int FfiOHOSWebviewCtlLoadUrlWithHeaders = 0;
FFI_EXPORT int FfiOHOSWebviewCtlLoadData = 0;
FFI_EXPORT int FfiOHOSWebviewCtlRefresh = 0;
FFI_EXPORT int FfiOHOSWebviewCtlGetUserAgent = 0;
FFI_EXPORT int FfiOHOSWebviewCtlAccessForward = 0;
FFI_EXPORT int FfiOHOSWebviewCtlAccessBackward = 0;
FFI_EXPORT int FfiOHOSWebviewCtlSetCustomUserAgent = 0;
FFI_EXPORT int FfiOHOSWebviewCtlGetCustomUserAgent = 0;
FFI_EXPORT int FfiOHOSWebviewCtlRunJavaScript = 0;
FFI_EXPORT int FfiOHOSWebviewCtlRegisterJavaScriptProxy = 0;
FFI_EXPORT int FfiOHOSWebviewCtlGetUrl = 0;
FFI_EXPORT int FfiOHOSWebviewCtlGetOriginalUrl = 0;
FFI_EXPORT int FfiOHOSWebviewCtlPageUp = 0;
FFI_EXPORT int FfiOHOSWebviewCtlPageDown = 0;
FFI_EXPORT int FfiOHOSWebviewCtlScrollTo = 0;
FFI_EXPORT int FfiOHOSWebviewCtlScrollBy = 0;
FFI_EXPORT int FfiOHOSWebviewCtlForward = 0;
FFI_EXPORT int FfiOHOSWebviewCtlBackward = 0;
FFI_EXPORT int FfiOHOSWebviewCtlBackOrForward = 0;
FFI_EXPORT int FfiOHOSWebviewCtlGetPageHeight = 0;
FFI_EXPORT int FfiOHOSWebviewCtlGetTitle = 0;
FFI_EXPORT int FfiOHOSWebviewCtlZoom = 0;
FFI_EXPORT int FfiOHOSWebviewCtlZoomIn = 0;
FFI_EXPORT int FfiOHOSWebviewCtlZoomOut = 0;
FFI_EXPORT int FfiOHOSWebviewCtlClearHistory = 0;
FFI_EXPORT int FfiOHOSWebviewCtlAccessStep = 0;
FFI_EXPORT int FfiOHOSWebviewCtlOnActive = 0;
FFI_EXPORT int FfiOHOSWebviewCtlOnInactive = 0;
FFI_EXPORT int FfiOHOSWebviewCtlGetHitTest = 0;
FFI_EXPORT int FfiOHOSWebviewCtlGetHitTestValue = 0;
FFI_EXPORT int FfiOHOSWebviewCtlStoreWebArchive = 0;
FFI_EXPORT int FfiOHOSWebviewCtlEnableSafeBrowsing = 0;
FFI_EXPORT int FfiOHOSWebviewCtlIsSafeBrowsingEnabled = 0;
FFI_EXPORT int FfiOHOSWebviewCtlGetSecurityLevel = 0;
FFI_EXPORT int FfiOHOSWebviewCtlIsIncognitoMode = 0;
FFI_EXPORT int FfiOHOSWebviewCtlRemoveCache = 0;
FFI_EXPORT int FfiOHOSWebviewCtlGetBackForwardEntries = 0;
FFI_EXPORT int FfiOHOSWebviewCtlStop = 0;

// webCookieView
FFI_EXPORT int FfiOHOSCookieMgrClearSessionCookieSync = 0;
FFI_EXPORT int FfiOHOSCookieMgrClearAllCookiesSync = 0;
FFI_EXPORT int FfiOHOSCookieMgrExistCookie = 0;
FFI_EXPORT int FfiOHOSCookieMgrIsThirdPartyCookieAllowed = 0;
FFI_EXPORT int FfiOHOSCookieMgrPutAcceptThirdPartyCookieEnabled = 0;
FFI_EXPORT int FfiOHOSCookieMgrIsCookieAllowed = 0;
FFI_EXPORT int FfiOHOSCookieMgrPutAcceptCookieEnabled = 0;
FFI_EXPORT int FfiOHOSCookieMgrConfigCookieSync = 0;
FFI_EXPORT int FfiOHOSCookieMgrFetchCookieSync = 0;

// BackForwardList
FFI_EXPORT int FfiOHOSBackForwardListCurrentIndex = 0;
FFI_EXPORT int FfiOHOSBackForwardListSize = 0;
FFI_EXPORT int FfiOHOSGetItemAtIndex = 0;
}