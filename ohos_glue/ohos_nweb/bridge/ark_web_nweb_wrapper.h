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

#ifndef ARK_WEB_NWEB_WRAPPER_H_
#define ARK_WEB_NWEB_WRAPPER_H_
#pragma once

#include "include/nweb.h"
#include "ohos_nweb/include/ark_web_nweb.h"

namespace OHOS::ArkWeb {

using ArkWebBlurReason = OHOS::NWeb::BlurReason;
using ArkWebFocusReason = OHOS::NWeb::FocusReason;
using ArkWebImageColorType = OHOS::NWeb::ImageColorType;
using ArkWebImageAlphaType = OHOS::NWeb::ImageAlphaType;
using ArkWebNestedScrollMode = OHOS::NWeb::NestedScrollMode;

class ArkWebNWebWrapper : public OHOS::NWeb::NWeb {
public:
    ArkWebNWebWrapper(ArkWebRefPtr<ArkWebNWeb> ark_web_nweb);
    ~ArkWebNWebWrapper() = default;

    void Resize(uint32_t width, uint32_t height, bool is_keyboard) override;

    void OnPause() override;

    void OnContinue() override;

    void OnDestroy() override;

    void OnFocus(const ArkWebFocusReason& focus_reason) override;

    void OnBlur(const ArkWebBlurReason& blur_reason) override;

    void OnTouchPress(int32_t id, double x, double y, bool from_overlay) override;

    void OnTouchRelease(int32_t id, double x, double y, bool from_overlay) override;

    void OnTouchMove(int32_t id, double x, double y, bool from_overlay) override;

    void OnTouchMove(const std::vector<std::shared_ptr<OHOS::NWeb::NWebTouchPointInfo>>& touch_point_infos,
        bool from_overlay) override;

    void OnTouchCancel() override;

    void OnNavigateBack() override;

    bool SendKeyEvent(int32_t key_code, int32_t key_action) override;

    void SendMouseWheelEvent(double x, double y, double delta_x, double delta_y) override;

    void SendMouseEvent(int x, int y, int button, int action, int count) override;

    /**
     * @brief Loads the given URL.
     *
     * @param url: the URL of the resource to load This value cannot be null.
     *
     * @return title string for the current page.
     */
    int Load(const std::string& url) override;

    /**
     * @brief Gets whether this NWeb has a back history item.
     *
     * @return true if this NWeb has a back history item
     */
    bool IsNavigatebackwardAllowed() override;

    /**
     * @brief Gets whether this NWeb has a forward history item.
     *
     * @return true if this NWeb has a forward history item
     */
    bool IsNavigateForwardAllowed() override;

    /**
     * @brief Gets whether this NWeb has a back or forward history item for number
     *        of steps.
     *
     * @param num_steps: the negative or positive number of steps to move the
     *        history
     *
     * @return true if this NWeb has a forward history item
     */
    bool CanNavigateBackOrForward(int num_steps) override;

    /**
     * @brief Goes back in the history of this NWeb.
     */
    void NavigateBack() override;

    /**
     * @brief Goes forward in the history of this NWeb.
     */
    void NavigateForward() override;

    /**
     * @brief Goes to the history item that is the number of steps away from the
     *        current item.
     */
    void NavigateBackOrForward(int step) override;

    /**
     * @brief Delete back and forward history list.
     */
    void DeleteNavigateHistory() override;

    /**
     * @brief Reloads the current URL.
     */
    void Reload() override;

    /**
     * @brief Performs a zoom operation in this NWeb.
     *
     * @param zoom_factor: the zoom factor to apply. The zoom factor will be
     *        clamped to the NWeb's zoom limits. This value must be in the range
     *        0.01 to 100.0 inclusive.
     *
     * @return the error id.
     */
    int Zoom(float zoom_factor) override;

    /**
     * @brief Performs a zooming in operation in this NWeb.
     *
     * @return the error id.
     */
    int ZoomIn() override;

    /**
     * @brief Performs a zooming out operation in this NWeb.
     *
     * @return the error id.
     */
    int ZoomOut() override;

    /**
     * @brief Stops the current load.
     *
     * @param code string: javascript code
     */
    void Stop() override;

    /**
     * @brief ExecuteJavaScript
     */
    void ExecuteJavaScript(const std::string& code) override;

    /**
     * @brief ExecuteJavaScript plus
     *
     * @param code: javascript code
     * @param callback: javascript running result
     */
    void ExecuteJavaScript(const std::string& code, std::shared_ptr<OHOS::NWeb::NWebMessageValueCallback> callback,
        bool extention) override;

    /**
     * @brief Gets the NWebPreference object used to control the settings for this
     *        NWeb.
     *
     * @return a NWebPreference object that can be used to control this NWeb's
     *         settings This value cannot be null.
     */
    std::shared_ptr<OHOS::NWeb::NWebPreference> GetPreference() override;

    /**
     * @brief Gets the web id.
     *
     * @return the web id
     */
    unsigned int GetWebId() override;

    /**
     * @brief Gets the last hit test result.
     *
     * @return the last HitTestResult
     */
    std::shared_ptr<OHOS::NWeb::HitTestResult> GetHitTestResult() override;

    /**
     * @brief Sets the background color for this view.
     *
     * @param color: the color of the background
     */
    void PutBackgroundColor(int color) override;

    /**
     * @brief Sets the initla scale for the page.
     *
     * @param scale: the initla scale of the page.
     */
    void InitialScale(float scale) override;

    /**
     * @brief Sets the NWebDownloadCallback that will receive download event. This
     *        will replace the current handler.
     *
     * @param download_listener: download listener
     */
    void PutDownloadCallback(std::shared_ptr<OHOS::NWeb::NWebDownloadCallback> download_listener) override;

    /**
     * @brief Set the NWebAccessibilityEventCallback that will receive
     *        accessibility event. This will replace the current handler.
     *
     * @param accessibility_event_listener: accessibility event listener
     */
    void PutAccessibilityEventCallback(
        std::shared_ptr<OHOS::NWeb::NWebAccessibilityEventCallback> accessibility_event_listener) override;

    /**
     * @brief Set the accessibility id generator that will generate accessibility
     *        id for accessibility nodes in the web. This will replace the current
     *        handler.
     *
     * @param accessibility_id_generator: Accessibility id generator.
     */
    void PutAccessibilityIdGenerator(const AccessibilityIdGenerateFunc accessibility_id_generator) override;

    /**
     * @brief Set the NWebHandler that will receive various notifications and
     *        requests. This will replace the current handler.
     *
     * @param handler: an implementation of NWebHandler This value cannot be null.
     */
    void SetNWebHandler(std::shared_ptr<OHOS::NWeb::NWebHandler> handler) override;

    /**
     * @brief Gets the title for the current page.
     *
     * @return title string for the current page.
     */
    std::string Title() override;

    /**
     * @brief Gets the progress for the current page.
     *
     * @return progress for the current page.
     */
    int PageLoadProgress() override;

    /**
     * @brief Gets the height of the HTML content.
     *
     * @return the height of the HTML content.
     */
    int ContentHeight() override;

    /**
     * @brief Gets the current scale of this NWeb.
     *
     * @return the current scale
     */
    float Scale() override;

    /**
     * @brief Loads the given URL with additional HTTP headers, specified as a map
     *        from name to value. Note that if this map contains any of the
     *        headers that are set by default by this NWeb, such as those
     *        controlling caching, accept types or the User-Agent, their values
     *        may be overridden by this NWeb's defaults.
     *
     * @param url: the URL of the resource to load This value cannot be null.
     * @param additional_http_headers: additional http headers
     */
    int Load(const std::string& url, const std::map<std::string, std::string>& additional_http_headers) override;

    /**
     * @brief Loads the given data into this NWeb, using baseUrl as the base URL
     *        for the content. The base URL is used both to resolve relative URLs
     *        and when applying JavaScript's same origin policy. The historyUrl is
     *        used for the history entry.
     *
     * @param base_url: the URL to use as the page's base URL. If null defaults to
     *        'about:blank'. This value may be null.
     * @param data: the URL to use as the page's base URL. If null defaults to
     *        'about:blank'. This value may be null.
     * @param mime_type: the MIME type of the data, e.g. 'text/html'. This value
     *        may be null.
     * @param encoding: the encoding of the data This value may be null.
     * @param history_url: the URL to use as the history entry. If null defaults
     *        to 'about:blank'. If non-null, this must be a valid URL. This value
     *        may be null.
     */
    int LoadWithDataAndBaseUrl(const std::string& base_url, const std::string& data, const std::string& mime_type,
        const std::string& encoding, const std::string& history_url) override;

    /**
     * @brief Loads the given data into this NWeb.
     *
     * @param data: the URL to use as the page's base URL. If null defaults to
     *        'about:blank'. This value may be null.
     * @param mime_type: the MIME type of the data, e.g. 'text/html'. This value
     *        may be null.
     * @param encoding: the encoding of the data This value may be null.
     */
    int LoadWithData(const std::string& data, const std::string& mime_type, const std::string& encoding) override;

    /**
     * @brief RegisterArkJSfunction
     *
     * @param object_name  String: objector name
     * @param method_list vector<String>: vector list ,method list
     * @param object_id int32_t: object id
     */
    void RegisterArkJSfunction(
        const std::string& object_name, const std::vector<std::string>& method_list, const int32_t object_id) override;

    /**
     * @brief UnregisterArkJSfunction
     *
     * @param object_name: objector name
     * @param method_list: vector list ,method list
     */
    void UnregisterArkJSfunction(const std::string& object_name, const std::vector<std::string>& method_list) override;

    /**
     * @brief SetNWebJavaScriptResultCallBack
     *
     * @param callback: callback client
     */
    void SetNWebJavaScriptResultCallBack(std::shared_ptr<OHOS::NWeb::NWebJavaScriptResultCallBack> callback) override;

    /**
     * @brief Set the NWebFindCallback that will receive find event. This will
     *        replace the current handler.
     *
     * @param find_listener: find callback
     */
    void PutFindCallback(std::shared_ptr<OHOS::NWeb::NWebFindCallback> find_listener) override;

    /**
     * @brief Finds all instances of find on the page and highlights them,
     *        asynchronously.
     *
     * @param search_str: target string to find.
     */
    void FindAllAsync(const std::string& search_str) override;

    /**
     * @brief Clears the highlighting surrounding text matches created by
     *        findAllAsync
     */
    void ClearMatches() override;

    /**
     * @brief Highlights and scrolls to the next match found by
     *        findAllAsync(String), wrapping around page boundaries as necessary.
     *
     * @param forward: find back or forward:
     */
    void FindNext(const bool forward) override;

    /**
     * @brief Saves the current view as a web archive.
     *
     * @param base_name: the filename where the archive should be placed This
     *        value cannot be null.
     * @param auto_name: if false, takes basename to be a file. If true, basename
     *        is assumed to be a directory in which a filename will be chosen
     *        according to the URL of the current page.
     */
    void StoreWebArchive(const std::string& base_name, bool auto_name,
        std::shared_ptr<OHOS::NWeb::NWebStringValueCallback> callback) override;

    /**
     * @brief creating two ends of a message channel.
     *
     * @return the web message ports get from nweb.
     */
    std::vector<std::string> CreateWebMessagePorts() override;

    /**
     * @brief Posts MessageEvent to the main frame.
     *
     * @param message: message send to mmain frame.
     * @param ports: the web message ports send to main frame.
     * @param target_uri: the uri which can received the ports.
     */
    void PostWebMessage(
        const std::string& message, const std::vector<std::string>& ports, const std::string& target_uri) override;

    /**
     * @brief close the message port.
     *
     * @param port_handle: the port to close.
     */
    void ClosePort(const std::string& port_handle) override;

    /**
     * @brief use the port to send message.
     *
     * @param port_handle: the port to send message.
     * @param data: the message to send.
     */
    void PostPortMessage(const std::string& port_handle, std::shared_ptr<OHOS::NWeb::NWebMessage> data) override;

    /**
     * @brief set the callback of the message port.
     *
     * @param port_handle: the port to set callback.
     * @param callback: to reveive the result when the other port post message.
     */
    void SetPortMessageCallback(
        const std::string& port_handle, std::shared_ptr<OHOS::NWeb::NWebMessageValueCallback> callback) override;

    void SendDragEvent(std::shared_ptr<OHOS::NWeb::NWebDragEvent> drag_event) override;

    /**
     * @brief Clear ssl cache.
     */
    void ClearSslCache() override;

    /**
     * @brief get web page url.
     *
     * @return web page url.
     */
    std::string GetUrl() override;

    /**
     * @brief Clears the client authentication certificate Cache in the Web.
     */
    void ClearClientAuthenticationCache() override;

    /**
     * @brief set the locale name of current system setting..
     *
     * @param region: the locale name of current system setting.
     */
    void UpdateLocale(const std::string& language, const std::string& region) override;

    /**
     * @brief get original url of the request.
     *
     * @return original url.
     */
    const std::string GetOriginalUrl() override;

    /**
     * @brief get original url of the request.
     *
     * @param data: raw image data of the icon.
     * @param width: width of the icon.
     * @param height: height of the icon.
     * @param color_type: the color type of the icon.
     * @param alpha_type: the alpha type of the icon.
     *
     * @return the result of get favicon.
     */
    bool GetFavicon(const void** data, size_t& width, size_t& height, ArkWebImageColorType& color_type,
        ArkWebImageAlphaType& alpha_type) override;

    /**
     * @brief set the network status, just notify the webview to change the JS
     *        navigatoer.online.
     *
     * @param available: width of the icon.
     */
    void PutNetworkAvailable(bool available) override;

    /**
     * @brief web has image or not.
     *
     * @param callback: has image or not
     */
    void HasImages(std::shared_ptr<OHOS::NWeb::NWebBoolValueCallback> callback) override;

    /**
     * @brief web remove cache.
     *
     * @param include_disk_files: if false, only the RAM cache is removed
     */
    void RemoveCache(bool include_disk_files) override;

    /**
     * @brief web has image or not.
     */
    std::shared_ptr<OHOS::NWeb::NWebHistoryList> GetHistoryList() override;

    /**
     * @brief Set the NWebReleaseSurfaceCallback that will receive release surface
     *        event. This will replace the current handler.
     *
     * @param release_surface_listener: release surface listener
     */
    void PutReleaseSurfaceCallback(
        std::shared_ptr<OHOS::NWeb::NWebReleaseSurfaceCallback> release_surface_listener) override;

    /**
     * @brief Get web back forward state.
     *
     * @return web back forward state.
     */
    std::vector<uint8_t> SerializeWebState() override;

    /**
     * @brief Restore web back forward state.
     *
     * @param state: web back forward state.
     */
    bool RestoreWebState(const std::vector<uint8_t>& state) override;

    /**
     * @brief Move page up.
     *
     * @param top: whether move to the top.
     */
    void PageUp(bool top) override;

    /**
     * @brief Move page down.
     *
     * @param bottom: whether move to the bottom.
     */
    void PageDown(bool bottom) override;

    /**
     * @brief Scroll to the position.
     *
     * @param x: horizontal coordinate.
     * @param y: vertical coordinate.
     */
    void ScrollTo(float x, float y) override;

    /**
     * @brief Scroll by the delta distance.
     *
     * @param delta_x: horizontal offset.
     * @param delta_y: vertical offset.
     */
    void ScrollBy(float delta_x, float delta_y) override;

    /**
     * @brief Slide scroll by the speed.
     *
     * @param vx: horizontal slide speed.
     * @param vy: vertical slide speed.
     */
    void SlideScroll(float vx, float vy) override;

    /**
     * @brief Get current website certificate.
     *
     * @param cert_chain_data: current website certificate array.
     * @param is_single_cert: true if only get one certificate of current website,
     *        false if get certificate chain of the website.
     *
     * @return true if get certificate successfully, otherwise false.
     */
    bool GetCertChainDerData(std::vector<std::string>& cert_chain_data, bool is_single_cert) override;

    /**
     * @brief Set screen offset.
     *
     * @param x: the offset in x direction.
     * @param y: the offset in y direction.
     */
    void SetScreenOffSet(double x, double y) override;

    /**
     * @brief Set audio muted.
     *
     * @param muted: Aduio mute state.
     */
    void SetAudioMuted(bool muted) override;

    /**
     * @brief Set should frame submission before draw.
     *
     * @param should: whether wait render frame submission.
     */
    void SetShouldFrameSubmissionBeforeDraw(bool should) override;

    /**
     * @brief Notify whether the popup window is initialized successfully.
     *
     * @param result: whether success.
     */
    void NotifyPopupWindowResult(bool result) override;

    /**
     * @brief Set audio resume interval.
     *
     * @param resume_interval: Aduio resume interval.
     */
    void SetAudioResumeInterval(int32_t resume_interval) override;

    /**
     * @brief Set audio exclusive state.
     *
     * @param audio_exclusive: Aduio exclusive state.
     */
    void SetAudioExclusive(bool audio_exclusive) override;

    /**
     * @brief Rigest the keep srceen on interface.
     *
     * @param window_id: the window id.
     * @param callback the screenon handle callback.
     */
    void RegisterScreenLockFunction(
        int32_t window_id, std::shared_ptr<OHOS::NWeb::NWebScreenLockCallback> callback) override;

    /**
     * @brief UnRigest the keep srceen on interface.
     *
     * @param window_id: the window id.
     */
    void UnRegisterScreenLockFunction(int32_t window_id) override;

    /**
     * @brief Notify memory level.
     *
     * @param level: the memory level.
     */
    void NotifyMemoryLevel(int32_t level) override;

    /**
     * @brief Notify webview window status.
     */
    void OnWebviewHide() override;

    void OnWebviewShow() override;

    /**
     * @brief Get drag data.
     *
     * @return the drag data.
     */
    std::shared_ptr<OHOS::NWeb::NWebDragData> GetOrCreateDragData() override;

    /**
     * @brief Prefetch the resources required by the page, but will not execute js
     *        or render the page.
     *
     * @param url: Which url to preresolve/preconnect.
     * @param additional_http_headers: Additional HTTP request header of the URL.
     */
    void PrefetchPage(
        const std::string& url, const std::map<std::string, std::string>& additional_http_headers) override;

    /**
     * @brief Set the window id.
     */
    void SetWindowId(uint32_t window_id) override;

    /**
     * @brief Notify that browser was occluded by other windows.
     */
    void OnOccluded() override;

    /**
     * @brief Notify that browser was unoccluded by other windows.
     */
    void OnUnoccluded() override;

    /**
     * @brief Set the token.
     */
    void SetToken(void* token) override;

    /**
     * @brief Set the nested scroll mode.
     */
    void SetNestedScrollMode(const ArkWebNestedScrollMode& nested_scroll_mode) override;

    /**
     * @brief Set enable lower the frame rate.
     */
    void SetEnableLowerFrameRate(bool enabled) override;

    /**
     * @brief Set the property values for width, height, and keyboard height.
     */
    void SetVirtualKeyBoardArg(int32_t width, int32_t height, double keyboard) override;

    /**
     * @brief Set the virtual keyboard to override the web status.
     */
    bool ShouldVirtualKeyboardOverlay() override;

    /**
     * @brief Set draw rect.
     */
    void SetDrawRect(int32_t x, int32_t y, int32_t width, int32_t height) override;

    /**
     * @brief Set draw mode.
     */
    void SetDrawMode(int32_t mode) override;

    /**
     * @brief Create web print document adapter.
     */
    void* CreateWebPrintDocumentAdapter(const std::string& job_name) override;

    /**
     * @brief Loads the URL with postData using "POST" method into this WebView.
     *        If url is not a network URL, it will be loaded with loadUrl(String)
     * instead.
     *
     * @param url: the URL of the resource to load This value cannot be null.
     * @param post_data: the data will be passed to "POST" request, whilch must be
     *        "application/x-www-form-urlencoded" encoded.
     *
     * @return title string for the current page.
     */
    int PostUrl(const std::string& url, const std::vector<char>& post_data) override;

    /**
     * @brief Inject the JavaScript before WebView load the DOM tree.
     */
    void JavaScriptOnDocumentStart(const std::map<std::string, std::vector<std::string>>& script_items) override;

    /**
     * @brief Execute an accessibility action on an accessibility node in the
     *        browser.
     *
     * @param accessibility_id: The id of the accessibility node.
     * @param action: The action to be performed on the accessibility node.
     */
    void ExecuteAction(int64_t accessibility_id, uint32_t action) override;

    /**
     * @brief Get the information of the focused accessibility node on the given
     *        accessibility node in the browser.
     *
     * @param accessibility_id: Indicate the accessibility id of the parent node
     *        of the focused accessibility node.
     * @param is_accessibility_focus: Indicate whether the focused accessibility
     *        node is accessibility focused or input focused.
     *
     * @return The obtained information of the accessibility node.
     */
    std::shared_ptr<OHOS::NWeb::NWebAccessibilityNodeInfo> GetFocusedAccessibilityNodeInfo(
        int64_t accessibility_id, bool is_accessibility_focus) override;

    /**
     * @brief Get the information of the accessibility node by its accessibility
     *        id in the browser.
     *
     * @param accessibility_id: The accessibility id of the accessibility node.
     *
     * @return The obtained information of the accessibility node.
     */
    std::shared_ptr<OHOS::NWeb::NWebAccessibilityNodeInfo> GetAccessibilityNodeInfoById(
        int64_t accessibility_id) override;

    /**
     * @brief Get the information of the accessibility node by focus move in the
     *        browser.
     *
     * @param accessibility_id: The accessibility id of the original accessibility
     *        node.
     * @param direction: The focus move direction of the original accessibility
     *        node.
     *
     * @return The obtained information of the accessibility node.
     */
    std::shared_ptr<OHOS::NWeb::NWebAccessibilityNodeInfo> GetAccessibilityNodeInfoByFocusMove(
        int64_t accessibility_id, int32_t direction) override;

    /**
     * @brief Set the accessibility state in the browser.
     *
     * @param state: Indicate whether the accessibility state is enabled or
     *        disabled.
     */
    void SetAccessibilityState(bool state) override;

    /**
     * @brief Get whether need soft keyboard.
     *
     * @return true if need soft keyboard, otherwise false.
     */
    bool NeedSoftKeyboard() override;

    /**
     * @brief Discard the webview window.
     *
     * @return true if the discarding success, otherwise false.
     */
    bool Discard() override;

    /**
     * @brief Reload the webview window that has been discarded before.
     *
     * @return true if the discarded window reload success, otherwise false.
     */
    bool Restore() override;

    /**
     * @brief Get the security level of current page.
     *
     * @return security level for current page.
     */
    int GetSecurityLevel() override;

    /**
     * @brief CallH5Function
     *
     * @param routingId         int32_t: the h5 frame routing id
     * @param h5ObjectId        int32_t: the h5 side object id
     * @param h5MethodName      string: the h5 side object method name
     * @param args              vector<shared_ptr<NWebValue>>: the call args
     */
    void CallH5Function(int32_t routingId, int32_t h5ObjectId, const std::string& h5MethodName,
        const std::vector<std::shared_ptr<OHOS::NWeb::NWebValue>>& args) override;

    /**
     * @brief Get web weather has been set incognito mode.
     *
     * @return true if web is in incognito mode; otherwise fase.
     */
    bool IsIncognitoMode() override;

    /**
     * @brief Register native function.
     */
    void RegisterNativeArkJSFunction(
        const char* objName, const std::vector<std::shared_ptr<OHOS::NWeb::NWebJsProxyCallback>>& callbacks) override;

    /**
     * @brief Unregister native function.
     */
    void UnRegisterNativeArkJSFunction(const char* objName) override;

    /**
     * @brief Register native valide callback function.
     */
    void RegisterNativeValideCallback(const char* webName, const NativeArkWebOnValidCallback callback) override;

    /**
     * @brief Register native destroy callback function.
     */
    void RegisterNativeDestroyCallback(const char* webName, const NativeArkWebOnValidCallback callback) override;

    /**
     * @brief Inject the JavaScript after WebView loads the DOM tree and run
     *        JavaScripts.
     */
    void JavaScriptOnDocumentEnd(const std::map<std::string, std::vector<std::string>>& script_items) override;

    /**
     * @brief Enable the ability to check website security risks.Illegal and
     *        fraudulent websites are mandatory enabled and cann't be disabled by
     *        this function.
     */
    void EnableSafeBrowsing(bool enable) override;

    /**
     * @brief Get whether checking website security risks is enabled.
     *
     * @return true if enable the ability to check website security risks else
     *         false.
     */
    bool IsSafeBrowsingEnabled() override;

    /**
     * @brief Set the ability to print web page background.
     *
     * @param enable Indicate whether the ability is enabled or disabled.
     */
    void SetPrintBackground(bool enable) override;

    /**
     * @brief Obtains whether to print the background of a web page.
     *
     * @return true if enable print web page background, otherwise false.
     */
    bool GetPrintBackground() override;

    /**
     * @brief Close fullScreen video.
     */
    void CloseAllMediaPresentations() override;

    /**
     * @brief Stop all audio and video playback on the web page.
     */
    void StopAllMedia() override;

    /**
     * @brief Restart playback of all audio and video on the web page.
     */
    void ResumeAllMedia() override;

    /**
     * @brief Pause all audio and video playback on the web page.
     */
    void PauseAllMedia() override;

    /**
     * @brief View the playback status of all audio and video on the web page.
     *
     * @return The playback status of all audio and video.
     */
    int GetMediaPlaybackState() override;

    /**
     * Enable the ability to intelligent tracking prevention, default disabled.
     */
    void EnableIntelligentTrackingPrevention(bool enable) override;

    /**
     * Get whether intelligent tracking prevention is enabled.
     * @return true if enable the ability intelligent tracking prevention; else
     * false.
     */
    bool IsIntelligentTrackingPreventionEnabled() const override;

    /**
     * @brief Start current camera.
     */
    /*--ark web()--*/
    void StartCamera() override;

    /**
     * @brief Stop current camera.
     */
    /*--ark web()--*/
    void StopCamera() override;

    /**
     * @brief Close current camera.
     */
    /*--ark web()--*/
    void CloseCamera() override;

    /**
     * @brief Obtains the last javascript proxy calling frame url.
     *
     * @return the url of last calling frame url.
     */
    /*--ark web()--*/
    std::string GetLastJavascriptProxyCallingFrameUrl() override;

    /**
     * @brief get pendingsize status.
     *
     * @return the result of last pendingsize status.
     */
    /*--ark web()--*/
    bool GetPendingSizeStatus() override;

    /**
     * Scroll by the delta distance or velocity takes the screen as a reference.
     *
     * @param delta_x horizontal offset in physical pixel.
     * @param delta_y vertical offset in physical pixel.
     * @param vx      horizontal velocity in physical pixel.
     * @param vx      vertical velocity in physical pixel.
     */
    /*--ark web()--*/
    void ScrollByRefScreen(float delta_x, float delta_y, float vx, float vy) override;

    /**
     * @brief ExecuteJavaScript with ashmem
     *
     * @param fd fd of the ashmem
     * @param scriptLength javascript code length
     * @param callback javascript running result
     * @param extention true if is extension
     */
    void ExecuteJavaScriptExt(const int fd, const size_t scriptLength,
        std::shared_ptr<OHOS::NWeb::NWebMessageValueCallback> callback, bool extention) override;

    /**
     * @brief Render process switch to background.
     */
    /*--ark web()--*/
    void OnRenderToBackground() override;

    /**
     * @brief Render process switch to foreground.
     */
    /*--ark web()--*/
    void OnRenderToForeground() override;

    /**
     * @brief Compile javascript and generate code cache.
     *
     * @param url url of javascript.
     * @param script javascript text content.
     * @param cacheOptions compile options and info.
     * @param callback callback will be called on getting the result of compiling
     * javascript.
     */
    /*--ark web()--*/
    void PrecompileJavaScript(const std::string& url, const std::string& script,
        std::shared_ptr<OHOS::NWeb::CacheOptions>& cacheOptions,
        std::shared_ptr<OHOS::NWeb::NWebMessageValueCallback> callback) override;

    void OnCreateNativeMediaPlayer(std::shared_ptr<OHOS::NWeb::NWebCreateNativeMediaPlayerCallback> callback) override;

    /**
     * @brief Web drag resize optimize.
     */
    /*--ark web()--*/
    void DragResize(uint32_t width, uint32_t height, uint32_t pre_height, uint32_t pre_width) override;

    void OnTouchCancelById(int32_t id, double x, double y, bool from_overlay) override;

    /**
     * @brief Set the params when the scale of WebView changed by pinch gestrue.
     *
     * @param scale: the scale factor to apply. The scale will be
     *        clamped to the pinch limits. This value must be in the range
     *        0.01 to 8.0 inclusive.
     * @param centerX: X-coordinate of the pinch center
     * @param centerX: Y-coordinate of the pinch center
     *
     * @return the error id.
     */
    /*--ark web()--*/
    int ScaleGestureChange(double scale, double centerX, double centerY) override;

    /**
     * @brief Inject offline resource into MemoryCache.
     *
     * @param url url of resource.
     * @param origin origin of resource.
     * @param resource data of resource.
     * @param response_headers response headers of resource.
     * @param type resource type.
     */
    /*--ark web()--*/
    void InjectOfflineResource(const std::string& url, const std::string& origin, const std::vector<uint8_t>& resource,
        const std::map<std::string, std::string>& responseHeaders, const int type) override;

    /*
     * @brief Terminate render process
     *
     * @return true if it was possible to terminate this render process, false
     * otherwise.
     */
    /*--ark web()--*/
    bool TerminateRenderProcess() override;

    /**
     * Get value of Autofill index.
     * @param index index value.
     */
    /*--ark web()--*/
    void SuggestionSelected(int32_t index) override;

        /**
     * @brief RegisterArkJSfunction
     *
     * @param object_name  String: objector name
     * @param method_list vector<String>: vector list, sync method list
     * @param async_method_list vector<String>: vector list, async method list
     * @param object_id int32_t: object id
     */
    /*--ark web()--*/
    void RegisterArkJSfunction(const std::string& object_name, const std::vector<std::string>& method_list,
        const std::vector<std::string>& async_method_list, const int32_t object_id) override;

    /**
     * @brief Send touchpad fling event.
     *
     * @param x location of x.
     * @param y location of y.
     * @param vx velocity of x.
     * @param vy velocity of y.
     */
    /*--ark web()--*/
    void SendTouchpadFlingEvent(double x, double y, double vx, double vy) override;

    /**
     * @brief Set draw mode.
     */
    void SetFitContentMode(int32_t mode) override;

    /**
     * @brief Get select info.
     */
    std::string GetSelectInfo() override;

    /**
     * @brief Render process switch to foreground.
     */
    /*--ark web()--*/
    void OnOnlineRenderToForeground() override;

    /**
     * @brief Notify that safe insets changed.
     */
    /*--ark web()--*/
    void OnSafeInsetsChange(int left, int top, int right, int bottom) override;

private:
    ArkWebRefPtr<ArkWebNWeb> ark_web_nweb_;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_NWEB_WRAPPER_H_
