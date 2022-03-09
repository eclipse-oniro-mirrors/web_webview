// Copyright (c) 2022 Huawei Device Co., Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "nweb_client_impl_test.h"

#include "nweb_test_log.h"
#include <fstream>
#include <cstring>
#include "nweb_url_resource_request.h"
#include "nweb_url_resource_response.h"
#include "utils.h"
#include "securec.h"

namespace OHOS::NWeb {
class JavaScriptResultCb : public NWebValueCallback<std::string> {
    void OnReceiveValue(std::string result) override
    {
        TESTLOG_I("JavaScript execute result = %{public}s", result.c_str());
    }
};
void NWebHandlerImplTest::OnProxyDied()
{
    TESTLOG_I("NWebHandlerImplTest::OnProxyDied called");
}

void NWebHandlerImplTest::SetNWeb(std::shared_ptr<NWeb> nweb)
{
    nwebweak_ = nweb;
}

void NWebHandlerImplTest::OnPageLoadEnd(int httpStatusCode, const std::string& url)
{
    TESTLOG_I("NWebHandlerImplTest::OnPageLoadend called, url=%{public}s", url.c_str());
    auto nwebShared = nwebweak_.lock();
    if (nwebShared == nullptr) {
        TESTLOG_E("nwebShared is nullptr");
        return;
    }

    if (url.find(EXECUTE_JAVASCRIPT_CALLBACK_HTML) != std::string::npos) {
        // invoke js function which is defined in html, test case 106
        std::string ss = "javascript:ExecuteJavaScriptTest()";
        std::shared_ptr<NWebValueCallback<std::string>> callback = std::make_shared<JavaScriptResultCb>();
        nwebShared->ExecuteJavaScript(ss, callback);
    }
}

void NWebHandlerImplTest::OnPageLoadBegin(const std::string& url)
{
    TESTLOG_I("NWebHandlerImplTest::OnPageLoadBegin called, url=%{public}s", url.c_str());
}

void NWebHandlerImplTest::OnPageLoadError(int errorCode,
                                          const std::string& description,
                                          const std::string& failingUrl)
{
    TESTLOG_I("NWebHandlerImplTest::OnPageLoadError called, url=%{public}s", failingUrl.c_str());
}

bool NWebHandlerImplTest::OnHandleInterceptUrlLoading(const std::string& url)
{
    TESTLOG_I("NWebHandlerImplTest::OnHandleInterceptUrlLoading called, url=%{public}s", url.c_str());
    return false;
}

void NWebHandlerImplTest::OnRouterPush(const std::string& param)
{
    TESTLOG_I("NWebHandlerImplTest::OnRouterPush called, url=%{public}s", param.c_str());
}

void NWebHandlerImplTest::OnMessage(const std::string& param)
{
    TESTLOG_I("NWebHandlerImplTest::OnMessage called, message=%{public}s", param.c_str());
}

const std::vector<std::string> NWebHandlerImplTest::VisitedUrlHistory()
{
    std::vector<std::string> vector_string;
    vector_string.push_back("https://www.qq.com");
    vector_string.push_back("file:///data/local/cef/cef_user_data/jingtai.html");
    return vector_string;
}

void NWebHandlerImplTest::OnResourceLoadError(std::shared_ptr<NWebUrlResourceRequest> request,
                                              std::shared_ptr<NWebUrlResourceError> error)
{
    TESTLOG_I("OnPageLoadError, url=%{public}s, errorCode=%{public}d, desc=%{public}s", request->Url().c_str(),
        error->ErrorCode(), error->ErrorInfo().c_str());
}
void NWebHandlerImplTest::OnHttpError(std::shared_ptr<NWebUrlResourceRequest> request,
                                      std::shared_ptr<NWebUrlResourceResponse> errorResponse)
{
    TESTLOG_I("OnHttpError, url=%{public}s, mimeType=%{public}s, is_main_frame=%{public}d," \
        "has_user_gesture=%{public}d", request->Url().c_str(),
        errorResponse->ResponseMimeType().c_str(), request->IsAboutMainFrame(), request->FromGesture());
}
void NWebHandlerImplTest::OnPageIcon(const void* data,
                                     size_t width,
                                     size_t height,
                                     ImageColorType colorType,
                                     ImageAlphaType alphaType)
{
    TESTLOG_I("OnPageIcon, width=%{public}d, height=%{public}d", width, height);
    size_t len = width * height * BITS_PER_PIXEL;
    char* data_temp = new char[len];
    if (memcpy_s(data_temp, len, data, len) != 0) {
        delete []data_temp;
        return;
    }
    DumpToBmp("/system/etc/webview/icon.bmp", data_temp, width, height);
    delete []data_temp;
    data_temp = nullptr;
}

void NWebHandlerImplTest::OnDesktopIconUrl(const std::string& iconUrl, bool precomposed)
{
    TESTLOG_I("OnDesktopIconUrl, iconUrl=%{public}s, precomposed=%{public}d", iconUrl.c_str(), precomposed);
}

void NWebHandlerImplTest::OnFocus()
{
    TESTLOG_I("NWebHandlerImplTest::OnFocus");
}

void NWebHandlerImplTest::OnLoadingProgress(int newProgress)
{
    TESTLOG_I("NWebHandlerImplTest::OnLoadingProgress progress=%{public}d", newProgress);
}

void NWebHandlerImplTest::OnPageTitle(const std::string &title)
{
    TESTLOG_I("NWebHandlerImplTest::OnTitle title=%{public}s", title.c_str());
}

void NWebHandlerImplTest::OnResource(const std::string &url)
{
    TESTLOG_I("NWebHandlerImplTest::OnResource url=%{public}s", url.c_str());
}

void NWebHandlerImplTest::OnGeolocationShow(const std::string& origin,
                                            NWebGeolocationCallbackInterface* callback)
{
    TESTLOG_I("NWebHandlerImplTest::OnGeolocationShow called, origin=%{public}s", origin.c_str());
    callback->GeolocationCallbackInvoke(origin, true, true);
}

void NWebHandlerImplTest::OnGeolocationHide()
{
    TESTLOG_I("NWebHandlerImplTest::OnGeolocationHide called");
}

void NWebHandlerImplTest::OnPermissionRequest(std::shared_ptr<NWebAccessRequest> request)
{
    int id = request->ResourceAcessId();
    TESTLOG_I("NWebHandlerImplTest::OnPermissionRequest called, origin=%{public}s, resourceId=%{public}d",
              request->Origin().c_str(), id);
    request->Agree(id);
}

void NWebHandlerImplTest::OnPermissionRequestCanceled(std::shared_ptr<NWebAccessRequest> request)
{
    int id = request->ResourceAcessId();
    TESTLOG_I("NWebHandlerImplTest::OnPermissionRequestCanceled called, origin=%{public}s, resourceId=%{public}d",
              request->Origin().c_str(), id);
    request->Refuse();
}
} // namespace OHOS::NWeb
