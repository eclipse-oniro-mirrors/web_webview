/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef WEBVIEW_FFI_H
#define WEBVIEW_FFI_H

#include <cstdint>
#include "ffi_remote_data.h"
#include "webview_utils.h"
#include "cj_common_ffi.h"

extern "C" {
    FFI_EXPORT int64_t FfiOHOSWebviewCtlConstructor();
    FFI_EXPORT int64_t FfiOHOSWebviewCtlConstructorWithWebTag(char *webTag);
    FFI_EXPORT void FfiOHOSWebviewCtlInitializeWebEngine();
    FFI_EXPORT void FfiOHOSWebviewCtlSetHttpDns(int32_t secureDnsMode, char* secureDnsConfig);
    FFI_EXPORT void FfiOHOSWebviewCtlSetWebDebuggingAccess(bool webDebuggingAccess);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlLoadUrl(int64_t id, char *url);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlLoadUrlWithHeaders(int64_t id, char *url, OHOS::Webview::ArrWebHeader headers);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlLoadData(int64_t id, OHOS::Webview::LoadDatas loadDatas);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlRefresh(int64_t id);
    FFI_EXPORT int32_t FFiOHOSWebviewCtlPreFetchPage(int64_t id, char* url);
    FFI_EXPORT int32_t FFiOHOSWebviewCtlPreFetchPageWithHeaders(int64_t id, char* url, OHOS::Webview::ArrWebHeader headers);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlSetAudioMuted(int64_t id, bool mute);
    FFI_EXPORT char *FfiOHOSWebviewCtlGetUserAgent(int64_t id, int32_t *errCode);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlSetConnectionTimeout(int32_t timeout);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlGetWebId(int64_t id, int32_t *errCode);
    FFI_EXPORT bool FfiOHOSWebviewCtlAccessForward(int64_t id, int32_t *errCode);
    FFI_EXPORT bool FfiOHOSWebviewCtlAccessBackward(int64_t id, int32_t *errCode);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlSetCustomUserAgent(int64_t id, char *cUserAgent);
    FFI_EXPORT RetDataCString FfiOHOSWebviewCtlGetCustomUserAgent(int64_t id);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlRunJavaScript(int64_t id, char* cScript,
        void (*callbackRef)(RetDataCString infoRef));
    FFI_EXPORT int32_t FfiOHOSWebviewCtlRegisterJavaScriptProxy(int64_t id,
        CArrI64 cFuncIds,  const char* cName, CArrString cMethodList);
    FFI_EXPORT RetDataCString FfiOHOSWebviewCtlGetUrl(int64_t id);
    FFI_EXPORT RetDataCString FfiOHOSWebviewCtlGetOriginalUrl(int64_t id);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlPageUp(int64_t id, bool top);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlPageDown(int64_t id, bool bottom);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlScrollTo(int64_t id, float x, float y);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlScrollBy(int64_t id, float deltaX, float deltaY);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlForward(int64_t id);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlBackward(int64_t id);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlBackOrForward(int64_t id, int32_t step);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlGetPageHeight(int64_t id, int32_t *errCode);
    FFI_EXPORT RetDataCString FfiOHOSWebviewCtlGetTitle(int64_t id);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlZoom(int64_t id, float factor);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlZoomIn(int64_t id);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlZoomOut(int64_t id);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlRequestFocus(int64_t id);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlClearHistory(int64_t id);
    FFI_EXPORT bool FfiOHOSWebviewCtlAccessStep(int64_t id, int32_t *errCode, int32_t step);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlOnActive(int64_t id);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlOnInactive(int64_t id);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlGetHitTest(int64_t id, int32_t *errCode);
    FFI_EXPORT RetDataCString FfiOHOSWebviewCtlGetHitTestValue(int64_t id, int32_t *errCode);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlStoreWebArchive(int64_t id, const char* cBaseName,
        bool autoName, void (*callbackRef)(RetDataCString infoRef));
    FFI_EXPORT int32_t FfiOHOSWebviewCtlEnableSafeBrowsing(int64_t id, bool enable);
    FFI_EXPORT bool FfiOHOSWebviewCtlIsSafeBrowsingEnabled(int64_t id, int32_t *errCode);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlGetSecurityLevel(int64_t id, int32_t *errCode);
    FFI_EXPORT bool FfiOHOSWebviewCtlIsIncognitoMode(int64_t id, int32_t *errCode);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlRemoveCache(int64_t id, bool clearRom);
    FFI_EXPORT int64_t FfiOHOSWebviewCtlGetBackForwardEntries(int64_t id, int32_t *errCode);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlStop(int64_t id);
    FFI_EXPORT int64_t FfiOHOSWebviewCtlGetFavicon(int64_t id, int32_t *errCode);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlPrepareForPageLoad(char *url, bool preconnectable, int32_t numSockets);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlSlideScroll(int64_t id, float vx, float vy);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlSetNetworkAvailable(int64_t id, bool enable);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlClearClientAuthenticationCache(int64_t id);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlClearSslChache(int64_t id);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlSearchNext(int64_t id, bool forward);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlClearMatches(int64_t id);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlSearchAllAsync(int64_t id, char *searchString);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlDeleteJavaScriptRegister(int64_t id, char *name);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlPostUrl(int64_t id, char *url, CArrUI8 buffer);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlSetDownloadDelegate(int64_t id, int64_t delegateId);
    FFI_EXPORT int32_t FfiOHOSWebviewCtlStartDownload(int64_t id, char *url);

    // BackForwardList
    FFI_EXPORT int32_t FfiOHOSBackForwardListCurrentIndex(int64_t id, int32_t *errCode);
    FFI_EXPORT int32_t FfiOHOSBackForwardListSize(int64_t id, int32_t *errCode);
    FFI_EXPORT OHOS::Webview::CHistoryItem FfiOHOSGetItemAtIndex(int64_t id, int32_t index, int32_t *errCode);

    // cookie_manager
    FFI_EXPORT const char* FfiOHOSCookieMgrFetchCookieSync(const char *url, bool incognitoMode, int32_t* errCode);
    FFI_EXPORT int32_t FfiOHOSCookieMgrConfigCookieSync(const char* url, const char* value, bool incognitoMode);
    FFI_EXPORT void FfiOHOSCookieMgrPutAcceptCookieEnabled(bool accept);
    FFI_EXPORT bool FfiOHOSCookieMgrIsCookieAllowed();
    FFI_EXPORT void FfiOHOSCookieMgrPutAcceptThirdPartyCookieEnabled(bool accept);
    FFI_EXPORT bool FfiOHOSCookieMgrIsThirdPartyCookieAllowed();
    FFI_EXPORT bool FfiOHOSCookieMgrExistCookie(bool incognitoMode);
    FFI_EXPORT void FfiOHOSCookieMgrClearAllCookiesSync(bool incognitoMode);
    FFI_EXPORT void FfiOHOSCookieMgrClearSessionCookieSync();

    // WebDownloadItemImpl
    FFI_EXPORT int64_t FfiOHOSWebDownloadItemImplConstructor();
    FFI_EXPORT RetDataCString FfiOHOSWebDownloadItemImplGetGuid(int64_t id);
    FFI_EXPORT int64_t FfiOHOSWebDownloadItemImplGetCurrentSpeed(int64_t id, int32_t *errCode);
    FFI_EXPORT int64_t FfiOHOSWebDownloadItemImplGetPercentComplete(int64_t id, int32_t *errCode);
    FFI_EXPORT int64_t FfiOHOSWebDownloadItemImplGetTotalBytes(int64_t id, int32_t *errCode);
    FFI_EXPORT int64_t FfiOHOSWebDownloadItemImplGetReceivedBytes(int64_t id, int32_t *errCode);
    FFI_EXPORT int32_t FfiOHOSWebDownloadItemImplGetState(int64_t id, int32_t *errCode);
    FFI_EXPORT int32_t FfiOHOSWebDownloadItemImplGetLastErrorCode(int64_t id, int32_t *errCode);
    FFI_EXPORT RetDataCString FfiOHOSWebDownloadItemImplGetMethod(int64_t id);
    FFI_EXPORT RetDataCString FfiOHOSWebDownloadItemImplGetMimeType(int64_t id);
    FFI_EXPORT RetDataCString FfiOHOSWebDownloadItemImplGetUrl(int64_t id);
    FFI_EXPORT RetDataCString FfiOHOSWebDownloadItemImplGetSuggestedFileName(int64_t id);
    FFI_EXPORT RetDataCString FfiOHOSWebDownloadItemImplGetFullPath(int64_t id);
    FFI_EXPORT int32_t FfiOHOSWebDownloadItemImplStart(int64_t id, char *downloadPath);
    FFI_EXPORT int32_t FfiOHOSWebDownloadItemImplCancel(int64_t id);
    FFI_EXPORT int32_t FfiOHOSWebDownloadItemImplPause(int64_t id);
    FFI_EXPORT int32_t FfiOHOSWebDownloadItemImplResume(int64_t id);
    FFI_EXPORT CArrUI8 FfiOHOSWebDownloadItemImplSerialize(int64_t id, int32_t *errCode);
    FFI_EXPORT int64_t FfiOHOSWebDownloadItemImplDeserialize(CArrUI8 serializedData, int32_t *errCode);
    
    // WebDownloadDelegateImpl
    FFI_EXPORT int64_t FfiOHOSWebDownloadDelegateImplConstructor();
    FFI_EXPORT void FfiOHOSWebDownloadDelegateImplOnBeforeDownload(int64_t id, void (*callback)(int64_t));
    FFI_EXPORT void FfiOHOSWebDownloadDelegateImplOnDownloadUpdated(int64_t id, void (*callback)(int64_t));
    FFI_EXPORT void FfiOHOSWebDownloadDelegateImplOnDownloadFinish(int64_t id, void (*callback)(int64_t));
    FFI_EXPORT void FfiOHOSWebDownloadDelegateImplOnDownloadFailed(int64_t id, void (*callback)(int64_t));

    // WebDownloadManagerImpl
    FFI_EXPORT void FfiOHOSWebDownloadManagerImplSetDownloadDelegate(int64_t delegateId);
    FFI_EXPORT int32_t FfiOHOSWebDownloadManagerImplResumeDownload(int64_t itemId);
}

#endif // WEBVIEW_FFI_H