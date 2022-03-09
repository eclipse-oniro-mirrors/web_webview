// Copyright (c) 2022 Huawei Device Co., Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NWEB_HANDLER_H
#define NWEB_HANDLER_H

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "nweb_access_request.h"
#include "nweb.h"
#include "nweb_console_log.h"
#include "nweb_geolocation_callback_interface.h"
#include "nweb_js_dialog_result.h"
#include "nweb_url_resource_error.h"
#include "nweb_url_resource_request.h"
#include "nweb_url_resource_response.h"

namespace OHOS::NWeb {
/**
 * @brief Describes how pixel bits encoder color data.
 */
enum class ImageColorType {
    // Unknown color type.
    COLOR_TYPE_UNKNOWN = -1,

    // RGBA with 8 bits per pixel (32bits total).
    COLOR_TYPE_RGBA_8888 = 0,

    // BGRA with 8 bits per pixel (32bits total).
    COLOR_TYPE_BGRA_8888 = 1,
};

/**
 * @brief Describes how to interpret the alpha value of a pixel.
 */
enum class ImageAlphaType {
    // Unknown alpha type.
    ALPHA_TYPE_UNKNOWN = -1,

    // No transparency. The alpha component is ignored.
    ALPHA_TYPE_OPAQUE = 0,

    // Transparency with pre-multiplied alpha component.
    ALPHA_TYPE_PREMULTIPLIED = 1,

    // Transparency with post-multiplied alpha component.
    ALPHA_TYPE_POSTMULTIPLIED = 2,
};

class OHOS_NWEB_EXPORT NWebHandler {
public:
    NWebHandler() = default;

    virtual ~NWebHandler() = default;

    virtual void SetNWeb(std::shared_ptr<NWeb> nweb) {}

    virtual void OnProxyDied() {}

    virtual void OnRouterPush(const std::string& param) {}

    virtual void OnMessage(const std::string& param) {}

    /**
     * @brief Notify the SDK that a web site has finished loading. This method is
     * called only for main frame.
     *
     * @param httpStatusCode The status code for the http request.
     * @param url The url of the web site.
     */
    virtual void OnPageLoadEnd(int httpStatusCode, const std::string& url) {}

    /**
     * @brief Notify the SDK that a web site has started loading. This method is
     * called once for each main frame load.
     *
     * @param url The url to be loaded.
     */
    virtual void OnPageLoadBegin(const std::string& url) {}

    /**
     * @brief Report a load error to the SDK.
     *
     * @param errorCode The error code.
     * @param description The error description.
     * @param failingUrl The failed url.
     */
    virtual void OnPageLoadError(int errorCode,
                                 const std::string& description,
                                 const std::string& failingUrl) {}

    /**
     * @brief Give the SDK a chance to decide wheather to continue loading the
     * url.
     *
     * @param url The url to be loaded.
     * @return true to cancel the loading, false to continue the loading.
     */
    virtual bool OnHandleInterceptUrlLoading(const std::string& url) {
        return false;
    }

    /**
     * @brief Notify the SDK that the nweb will load the resource specified by
     * the given url.
     *
     * @param url The url of the resource.
     */
    virtual void OnResource(const std::string& url) {}

    /**
     * @brief Notify the SDK of the changed document title.
     *
     * @param title The document title.
     */
    virtual void OnPageTitle(const std::string& title) {}

    /**
     * @brief Notify the SDK the current progress of loading a web site.
     *
     * @param newProgress Loading progress, an integer between 0 and 100.
     */
    virtual void OnLoadingProgress(int newProgress) {}

    /**
     * @brief Request display and focus for a new nweb.
     *
     */
    virtual void OnFocus() {}

    /**
     * @brief Obtains a list of all visited history items, used for link coloring
     *
     * @retval visited history
     */
    virtual const std::vector<std::string> VisitedUrlHistory() {
        return std::vector<std::string>();
    }

    /**
     * @brief Notify the host application of a resource request and allow the
     * application to return the data.
     *
     * @param request the resource response's MIME type, for example {
     * "text/html"}.
     *
     * @retval if NWebUrlResourceResponse is null ,No interception.
     */
    virtual std::shared_ptr<NWebUrlResourceResponse> OnHandleInterceptRequest(
        std::shared_ptr<NWebUrlResourceRequest> request) {
        return nullptr;
    }

    /**
     * @brief Report web resource loading error to the SDK. These errors usually
     * indicate inability to connect to the server.
     *
     * @param request The request information.
     * @param error The error information.
     */
    virtual void OnResourceLoadError(std::shared_ptr<NWebUrlResourceRequest> request,
                                     std::shared_ptr<NWebUrlResourceError> error) {}

    /**
     * @brief Notify the SDK that an HTTP error has been received from the server
     * while loading a resource.
     *
     * @param request The request information.
     * @param errorResponse The error occurred.
     */
    virtual void OnHttpError(std::shared_ptr<NWebUrlResourceRequest> request,
                             std::shared_ptr<NWebUrlResourceResponse> errorResponse) {}

    /**
     * @brief Notify the SDK of a new favicon for the current web site.
     *
     * @param data The raw image data for the icon.
     * @param width The width of the icon in pixel.
     * @param height The height of the icon in pixel.
     * @param color_type The color data encoding type.
     * @param alpha_type The alpha value of any pixel.
     */
    virtual void OnPageIcon(const void* data,
                            size_t width,
                            size_t height,
                            ImageColorType color_type,
                            ImageAlphaType alpha_type) {}

    /**
     * @brief Notify the SDK of the url for an touch icon.
     *
     * @param icon_url The icon url.
     * @param precomposed The touch icon type.
     */
    virtual void OnDesktopIconUrl(const std::string& icon_url, bool precomposed) {
    }

    /**
     * @brief Report a JavaScript console message to the host application.
     *
     * @param message Details of the console message.
     * @return Return true to stop the message from being output to the console.
     */
    virtual bool OnConsoleLog(const NWebConsoleLog& message) { return false; }

    /**
     * @brief Show prompt to ask for the geolocation permission.
     *
     * @param origin  String: the origin of the resource to get geolocation
     * @param callback  GeolocationCallbackInterface: callback to report
     * geolocation
     */
    virtual void OnGeolocationShow(const std::string& origin,
                                   NWebGeolocationCallbackInterface* callback) {}

    /**
     * @brief Notify the host application that the web page wants to display a
     * JavaScript alert() dialog.
     *
     * @param url  String: The url of the page requesting the dialog.
     * @param message  String: The message of the dialog.
     * @param result  std::shared_ptr<NWebJSDialogResult>: A NWebJSDialogResult to
     * confirm that the user closed the window.
     * @return To show a custom dialog, the app should return true.
     */
    virtual bool OnAlertDialogByJS(const std::string& url,
                                   const std::string& message,
                                   std::shared_ptr<NWebJSDialogResult> result) {
        return false;
    }

    /**
     * @brief Notify the host application that the web page wants to handle
     * JavaScript onbeforeunload.
     *
     * @param url  String: The url of the page requesting.
     * @param message  String: The message of the dialog.
     * @param result  std::shared_ptr<NWebJSDialogResult>: A NWebJSDialogResult to
     * confirm that the user closed the window.
     * @return To show a custom dialog, the app should return true.
     */
    virtual bool OnBeforeUnloadByJS(const std::string& url,
                                    const std::string& message,
                                    std::shared_ptr<NWebJSDialogResult> result) {
        return false;
    }

    /**
     * @brief Notify the host application that the web page wants to display a
     * JavaScript prompt() dialog.
     *
     * @param url  String: The url of the page requesting the dialog.
     * @param message  String: The message of the dialog.
     * @param defaultValue  String: The default value of the input message.
     * @param result  std::shared_ptr<NWebJSDialogResult>: A NWebJSDialogResult to
     * confirm that the user closed the window.
     * @return To show a custom dialog, the app should return true.
     */
    virtual bool OnPromptDialogByJs(const std::string& url,
                                    const std::string& message,
                                    const std::string& defaultValue,
                                    std::shared_ptr<NWebJSDialogResult> result) {
        return false;
    }

    /**
     * @brief Notify the host application that the web page wants to display a
     * JavaScript Confirm() dialog.
     *
     * @param url  String: The url of the page requesting the dialog.
     * @param message  String: The message of the dialog.
     * @param result  std::shared_ptr<NWebJSDialogResult>: A NWebJSDialogResult to
     * confirm that the user closed the window.
     * @return To show a custom dialog, the app should return true.
     */
    virtual bool OnConfirmDialogByJS(const std::string& url,
                                     const std::string& message,
                                     std::shared_ptr<NWebJSDialogResult> result) {
        return false;
    }

    /**
     * @brief Hide prompt to ask for the geolocation permission.
     */
    virtual void OnGeolocationHide() {}

    /**
     * @brief
     *
     * @param request  String:
     */
    virtual void OnPermissionRequest(std::shared_ptr<NWebAccessRequest> request) {}

    /**
     * @brief
     *
     * @param request  String:
     */
    virtual void OnPermissionRequestCanceled(std::shared_ptr<NWebAccessRequest> request) {}
};
}  // namespace OHOS::NWeb

#endif  // NWEB_HANDLER_H
