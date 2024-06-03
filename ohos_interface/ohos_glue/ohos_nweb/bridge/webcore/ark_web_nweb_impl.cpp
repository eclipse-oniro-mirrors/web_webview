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

#include "ohos_nweb/bridge/ark_web_nweb_impl.h"

#include "ohos_nweb/bridge/ark_web_accessibility_event_callback_wrapper.h"
#include "ohos_nweb/bridge/ark_web_accessibility_node_info_impl.h"
#include "ohos_nweb/bridge/ark_web_bool_value_callback_wrapper.h"
#include "ohos_nweb/bridge/ark_web_cache_options_wrapper.h"
#include "ohos_nweb/bridge/ark_web_core_struct_utils.h"
#include "ohos_nweb/bridge/ark_web_create_native_media_player_callback_wrapper.h"
#include "ohos_nweb/bridge/ark_web_download_callback_wrapper.h"
#include "ohos_nweb/bridge/ark_web_drag_data_impl.h"
#include "ohos_nweb/bridge/ark_web_drag_event_wrapper.h"
#include "ohos_nweb/bridge/ark_web_find_callback_wrapper.h"
#include "ohos_nweb/bridge/ark_web_handler_wrapper.h"
#include "ohos_nweb/bridge/ark_web_history_list_impl.h"
#include "ohos_nweb/bridge/ark_web_hit_test_result_impl.h"
#include "ohos_nweb/bridge/ark_web_js_result_callback_wrapper.h"
#include "ohos_nweb/bridge/ark_web_message_value_callback_wrapper.h"
#include "ohos_nweb/bridge/ark_web_preference_impl.h"
#include "ohos_nweb/bridge/ark_web_release_surface_callback_wrapper.h"
#include "ohos_nweb/bridge/ark_web_screen_lock_callback_wrapper.h"
#include "ohos_nweb/bridge/ark_web_spanstring_convert_html_callback_wrapper.h"
#include "ohos_nweb/bridge/ark_web_string_value_callback_wrapper.h"
#include "ohos_nweb/bridge/ark_web_system_configuration_wrapper.h"
#include "ohos_nweb/ctocpp/ark_web_js_proxy_callback_vector_ctocpp.h"
#include "ohos_nweb/ctocpp/ark_web_touch_point_info_vector_ctocpp.h"
#include "ohos_nweb/ctocpp/ark_web_value_vector_ctocpp.h"

#include "base/bridge/ark_web_bridge_macros.h"

namespace OHOS::ArkWeb {

using ArkWebBlurReason = OHOS::NWeb::BlurReason;
using ArkWebFocusReason = OHOS::NWeb::FocusReason;
using ArkWebImageColorType = OHOS::NWeb::ImageColorType;
using ArkWebImageAlphaType = OHOS::NWeb::ImageAlphaType;
using ArkWebNestedScrollMode = OHOS::NWeb::NestedScrollMode;

ArkWebNWebImpl::ArkWebNWebImpl(std::shared_ptr<OHOS::NWeb::NWeb> nweb_nweb) : nweb_nweb_(nweb_nweb) {}

void ArkWebNWebImpl::Resize(uint32_t width, uint32_t height, bool is_keyboard)
{
    nweb_nweb_->Resize(width, height, is_keyboard);
}

void ArkWebNWebImpl::OnPause()
{
    nweb_nweb_->OnPause();
}

void ArkWebNWebImpl::OnContinue()
{
    nweb_nweb_->OnContinue();
}

void ArkWebNWebImpl::OnDestroy()
{
    nweb_nweb_->OnDestroy();
}

void ArkWebNWebImpl::OnFocus(const int32_t& focus_reason)
{
    nweb_nweb_->OnFocus(static_cast<ArkWebFocusReason>(focus_reason));
}

void ArkWebNWebImpl::OnBlur(const int32_t& blur_reason)
{
    nweb_nweb_->OnBlur(static_cast<ArkWebBlurReason>(blur_reason));
}

void ArkWebNWebImpl::OnTouchPress(int32_t id, double x, double y, bool from_overlay)
{
    nweb_nweb_->OnTouchPress(id, x, y, from_overlay);
}

void ArkWebNWebImpl::OnTouchRelease(int32_t id, double x, double y, bool from_overlay)
{
    nweb_nweb_->OnTouchRelease(id, x, y, from_overlay);
}

void ArkWebNWebImpl::OnTouchMove(int32_t id, double x, double y, bool from_overlay)
{
    nweb_nweb_->OnTouchMove(id, x, y, from_overlay);
}

void ArkWebNWebImpl::OnTouchMove(const ArkWebTouchPointInfoVector& touch_point_infos, bool from_overlay)
{
    nweb_nweb_->OnTouchMove(ArkWebTouchPointInfoVectorStructToClass(touch_point_infos), from_overlay);
}

void ArkWebNWebImpl::OnTouchCancel()
{
    nweb_nweb_->OnTouchCancel();
}

void ArkWebNWebImpl::OnNavigateBack()
{
    nweb_nweb_->OnNavigateBack();
}

bool ArkWebNWebImpl::SendKeyEvent(int32_t key_code, int32_t key_action)
{
    return nweb_nweb_->SendKeyEvent(key_code, key_action);
}

void ArkWebNWebImpl::SendMouseWheelEvent(double x, double y, double delta_x, double delta_y)
{
    nweb_nweb_->SendMouseWheelEvent(x, y, delta_x, delta_y);
}

void ArkWebNWebImpl::SendMouseEvent(int x, int y, int button, int action, int count)
{
    nweb_nweb_->SendMouseEvent(x, y, button, action, count);
}

int ArkWebNWebImpl::Load(const ArkWebString& url)
{
    return nweb_nweb_->Load(ArkWebStringStructToClass(url));
}

bool ArkWebNWebImpl::IsNavigatebackwardAllowed()
{
    return nweb_nweb_->IsNavigatebackwardAllowed();
}

bool ArkWebNWebImpl::IsNavigateForwardAllowed()
{
    return nweb_nweb_->IsNavigateForwardAllowed();
}

bool ArkWebNWebImpl::CanNavigateBackOrForward(int num_steps)
{
    return nweb_nweb_->CanNavigateBackOrForward(num_steps);
}

void ArkWebNWebImpl::NavigateBack()
{
    nweb_nweb_->NavigateBack();
}

void ArkWebNWebImpl::NavigateForward()
{
    nweb_nweb_->NavigateForward();
}

void ArkWebNWebImpl::NavigateBackOrForward(int step)
{
    nweb_nweb_->NavigateBackOrForward(step);
}

void ArkWebNWebImpl::DeleteNavigateHistory()
{
    nweb_nweb_->DeleteNavigateHistory();
}

void ArkWebNWebImpl::Reload()
{
    nweb_nweb_->Reload();
}

int ArkWebNWebImpl::Zoom(float zoom_factor)
{
    return nweb_nweb_->Zoom(zoom_factor);
}

int ArkWebNWebImpl::ZoomIn()
{
    return nweb_nweb_->ZoomIn();
}

int ArkWebNWebImpl::ZoomOut()
{
    return nweb_nweb_->ZoomOut();
}

void ArkWebNWebImpl::Stop()
{
    nweb_nweb_->Stop();
}

void ArkWebNWebImpl::ExecuteJavaScript(const ArkWebString& code)
{
    nweb_nweb_->ExecuteJavaScript(ArkWebStringStructToClass(code));
}

void ArkWebNWebImpl::ExecuteJavaScript(
    const ArkWebString& code, ArkWebRefPtr<ArkWebMessageValueCallback> callback, bool extention)
{
    if (CHECK_REF_PTR_IS_NULL(callback)) {
        nweb_nweb_->ExecuteJavaScript(ArkWebStringStructToClass(code), nullptr, extention);
        return;
    }

    nweb_nweb_->ExecuteJavaScript(
        ArkWebStringStructToClass(code), std::make_shared<ArkWebMessageValueCallbackWrapper>(callback), extention);
}

ArkWebRefPtr<ArkWebPreference> ArkWebNWebImpl::GetPreference()
{
    std::shared_ptr<OHOS::NWeb::NWebPreference> nweb_preference = nweb_nweb_->GetPreference();
    if (CHECK_SHARED_PTR_IS_NULL(nweb_preference)) {
        return nullptr;
    }

    return new ArkWebPreferenceImpl(nweb_preference);
}

unsigned int ArkWebNWebImpl::GetWebId()
{
    return nweb_nweb_->GetWebId();
}

ArkWebRefPtr<ArkWebHitTestResult> ArkWebNWebImpl::GetHitTestResult()
{
    std::shared_ptr<OHOS::NWeb::HitTestResult> nweb_hit_test_result = nweb_nweb_->GetHitTestResult();
    if (CHECK_SHARED_PTR_IS_NULL(nweb_hit_test_result)) {
        return nullptr;
    }

    return new ArkWebHitTestResultImpl(nweb_hit_test_result);
}

void ArkWebNWebImpl::PutBackgroundColor(int color)
{
    nweb_nweb_->PutBackgroundColor(color);
}

void ArkWebNWebImpl::InitialScale(float scale)
{
    nweb_nweb_->InitialScale(scale);
}

void ArkWebNWebImpl::PutDownloadCallback(ArkWebRefPtr<ArkWebDownloadCallback> download_listener)
{
    if (CHECK_REF_PTR_IS_NULL(download_listener)) {
        nweb_nweb_->PutDownloadCallback(nullptr);
        return;
    }

    nweb_nweb_->PutDownloadCallback(std::make_shared<ArkWebDownloadCallbackWrapper>(download_listener));
}

void ArkWebNWebImpl::PutAccessibilityEventCallback(
    ArkWebRefPtr<ArkWebAccessibilityEventCallback> accessibility_event_listener)
{
    if (CHECK_REF_PTR_IS_NULL(accessibility_event_listener)) {
        nweb_nweb_->PutAccessibilityEventCallback(nullptr);
        return;
    }

    nweb_nweb_->PutAccessibilityEventCallback(
        std::make_shared<ArkWebAccessibilityEventCallbackWrapper>(accessibility_event_listener));
}

void ArkWebNWebImpl::PutAccessibilityIdGenerator(AccessibilityIdGenerateFunc accessibility_id_generator)
{
    nweb_nweb_->PutAccessibilityIdGenerator(accessibility_id_generator);
}

void ArkWebNWebImpl::SetNWebHandler(ArkWebRefPtr<ArkWebHandler> handler)
{
    if (CHECK_REF_PTR_IS_NULL(handler)) {
        nweb_nweb_->SetNWebHandler(nullptr);
        return;
    }

    nweb_nweb_->SetNWebHandler(std::make_shared<ArkWebHandlerWrapper>(handler));
}

ArkWebString ArkWebNWebImpl::Title()
{
    return ArkWebStringClassToStruct(nweb_nweb_->Title());
}

int ArkWebNWebImpl::PageLoadProgress()
{
    return nweb_nweb_->PageLoadProgress();
}

int ArkWebNWebImpl::ContentHeight()
{
    return nweb_nweb_->ContentHeight();
}

float ArkWebNWebImpl::Scale()
{
    return nweb_nweb_->Scale();
}

int ArkWebNWebImpl::Load(const ArkWebString& url, const ArkWebStringMap& additional_http_headers)
{
    return nweb_nweb_->Load(ArkWebStringStructToClass(url), ArkWebStringMapStructToClass(additional_http_headers));
}

int ArkWebNWebImpl::LoadWithDataAndBaseUrl(const ArkWebString& base_url, const ArkWebString& data,
    const ArkWebString& mime_type, const ArkWebString& encoding, const ArkWebString& history_url)
{
    return nweb_nweb_->LoadWithDataAndBaseUrl(ArkWebStringStructToClass(base_url), ArkWebStringStructToClass(data),
        ArkWebStringStructToClass(mime_type), ArkWebStringStructToClass(encoding),
        ArkWebStringStructToClass(history_url));
}

int ArkWebNWebImpl::LoadWithData(const ArkWebString& data, const ArkWebString& mime_type, const ArkWebString& encoding)
{
    return nweb_nweb_->LoadWithData(
        ArkWebStringStructToClass(data), ArkWebStringStructToClass(mime_type), ArkWebStringStructToClass(encoding));
}

void ArkWebNWebImpl::RegisterArkJSfunction(
    const ArkWebString& object_name, const ArkWebStringVector& method_list, const int32_t object_id)
{
    nweb_nweb_->RegisterArkJSfunction(
        ArkWebStringStructToClass(object_name), ArkWebStringVectorStructToClass(method_list), object_id);
}

void ArkWebNWebImpl::UnregisterArkJSfunction(const ArkWebString& object_name, const ArkWebStringVector& method_list)
{
    nweb_nweb_->UnregisterArkJSfunction(
        ArkWebStringStructToClass(object_name), ArkWebStringVectorStructToClass(method_list));
}

void ArkWebNWebImpl::SetNWebJavaScriptResultCallBack(ArkWebRefPtr<ArkWebJsResultCallback> callback)
{
    if (CHECK_REF_PTR_IS_NULL(callback)) {
        nweb_nweb_->SetNWebJavaScriptResultCallBack(nullptr);
        return;
    }

    nweb_nweb_->SetNWebJavaScriptResultCallBack(std::make_shared<ArkWebJsResultCallbackWrapper>(callback));
}

void ArkWebNWebImpl::PutFindCallback(ArkWebRefPtr<ArkWebFindCallback> find_listener)
{
    if (CHECK_REF_PTR_IS_NULL(find_listener)) {
        nweb_nweb_->PutFindCallback(nullptr);
        return;
    }

    nweb_nweb_->PutFindCallback(std::make_shared<ArkWebFindCallbackWrapper>(find_listener));
}

void ArkWebNWebImpl::FindAllAsync(const ArkWebString& search_str)
{
    nweb_nweb_->FindAllAsync(ArkWebStringStructToClass(search_str));
}

void ArkWebNWebImpl::ClearMatches()
{
    nweb_nweb_->ClearMatches();
}

void ArkWebNWebImpl::FindNext(const bool forward)
{
    nweb_nweb_->FindNext(forward);
}

void ArkWebNWebImpl::StoreWebArchive(
    const ArkWebString& base_name, bool auto_name, ArkWebRefPtr<ArkWebStringValueCallback> callback)
{
    if (CHECK_REF_PTR_IS_NULL(callback)) {
        nweb_nweb_->StoreWebArchive(ArkWebStringStructToClass(base_name), auto_name, nullptr);
        return;
    }

    nweb_nweb_->StoreWebArchive(
        ArkWebStringStructToClass(base_name), auto_name, std::make_shared<ArkWebStringValueCallbackWrapper>(callback));
}

ArkWebStringVector ArkWebNWebImpl::CreateWebMessagePorts()
{
    return ArkWebStringVectorClassToStruct(nweb_nweb_->CreateWebMessagePorts());
}

void ArkWebNWebImpl::PostWebMessage(
    const ArkWebString& message, const ArkWebStringVector& ports, const ArkWebString& target_uri)
{
    nweb_nweb_->PostWebMessage(ArkWebStringStructToClass(message), ArkWebStringVectorStructToClass(ports),
        ArkWebStringStructToClass(target_uri));
}

void ArkWebNWebImpl::ClosePort(const ArkWebString& port_handle)
{
    nweb_nweb_->ClosePort(ArkWebStringStructToClass(port_handle));
}

void ArkWebNWebImpl::PostPortMessage(const ArkWebString& port_handle, const ArkWebMessage& data)
{
    nweb_nweb_->PostPortMessage(ArkWebStringStructToClass(port_handle), data.nweb_message);
}

void ArkWebNWebImpl::SetPortMessageCallback(
    const ArkWebString& port_handle, ArkWebRefPtr<ArkWebMessageValueCallback> callback)
{
    if (CHECK_REF_PTR_IS_NULL(callback)) {
        nweb_nweb_->SetPortMessageCallback(ArkWebStringStructToClass(port_handle), nullptr);
        return;
    }

    nweb_nweb_->SetPortMessageCallback(
        ArkWebStringStructToClass(port_handle), std::make_shared<ArkWebMessageValueCallbackWrapper>(callback));
}

void ArkWebNWebImpl::SendDragEvent(ArkWebRefPtr<ArkWebDragEvent> drag_event)
{
    if (CHECK_REF_PTR_IS_NULL(drag_event)) {
        nweb_nweb_->SendDragEvent(nullptr);
        return;
    }

    nweb_nweb_->SendDragEvent(std::make_shared<ArkWebDragEventWrapper>(drag_event));
}

void ArkWebNWebImpl::ClearSslCache()
{
    nweb_nweb_->ClearSslCache();
}

ArkWebString ArkWebNWebImpl::GetUrl()
{
    return ArkWebStringClassToStruct(nweb_nweb_->GetUrl());
}

void ArkWebNWebImpl::ClearClientAuthenticationCache()
{
    nweb_nweb_->ClearClientAuthenticationCache();
}

void ArkWebNWebImpl::UpdateLocale(const ArkWebString& language, const ArkWebString& region)
{
    nweb_nweb_->UpdateLocale(ArkWebStringStructToClass(language), ArkWebStringStructToClass(region));
}

const ArkWebString ArkWebNWebImpl::GetOriginalUrl()
{
    return ArkWebStringClassToStruct(nweb_nweb_->GetOriginalUrl());
}

bool ArkWebNWebImpl::GetFavicon(const void** data, size_t& width, size_t& height, int& color_type, int& alpha_type)
{
    ArkWebImageColorType enum_color_type = ArkWebImageColorType::COLOR_TYPE_UNKNOWN;
    ArkWebImageAlphaType enum_alpha_type = ArkWebImageAlphaType::ALPHA_TYPE_UNKNOWN;
    bool result = nweb_nweb_->GetFavicon(data, width, height, enum_color_type, enum_alpha_type);
    color_type = static_cast<int>(enum_color_type);
    alpha_type = static_cast<int>(enum_alpha_type);
    return result;
}

void ArkWebNWebImpl::PutNetworkAvailable(bool available)
{
    nweb_nweb_->PutNetworkAvailable(available);
}

void ArkWebNWebImpl::HasImages(ArkWebRefPtr<ArkWebBoolValueCallback> callback)
{
    if (CHECK_REF_PTR_IS_NULL(callback)) {
        nweb_nweb_->HasImages(nullptr);
        return;
    }

    nweb_nweb_->HasImages(std::make_shared<ArkWebBoolValueCallbackWrapper>(callback));
}

void ArkWebNWebImpl::RemoveCache(bool include_disk_files)
{
    nweb_nweb_->RemoveCache(include_disk_files);
}

ArkWebRefPtr<ArkWebHistoryList> ArkWebNWebImpl::GetHistoryList()
{
    std::shared_ptr<OHOS::NWeb::NWebHistoryList> nweb_history_list = nweb_nweb_->GetHistoryList();
    if (CHECK_SHARED_PTR_IS_NULL(nweb_history_list)) {
        return nullptr;
    }

    return new ArkWebHistoryListImpl(nweb_history_list);
}

void ArkWebNWebImpl::PutReleaseSurfaceCallback(ArkWebRefPtr<ArkWebReleaseSurfaceCallback> release_surface_listener)
{
    if (CHECK_REF_PTR_IS_NULL(release_surface_listener)) {
        nweb_nweb_->PutReleaseSurfaceCallback(nullptr);
        return;
    }

    nweb_nweb_->PutReleaseSurfaceCallback(
        std::make_shared<ArkWebReleaseSurfaceCallbackWrapper>(release_surface_listener));
}

ArkWebUint8Vector ArkWebNWebImpl::SerializeWebState()
{
    return ArkWebBasicVectorClassToStruct<uint8_t, ArkWebUint8Vector>(nweb_nweb_->SerializeWebState());
}

bool ArkWebNWebImpl::RestoreWebState(const ArkWebUint8Vector& state)
{
    return nweb_nweb_->RestoreWebState(ArkWebBasicVectorStructToClass<uint8_t, ArkWebUint8Vector>(state));
}

void ArkWebNWebImpl::PageUp(bool top)
{
    nweb_nweb_->PageUp(top);
}

void ArkWebNWebImpl::PageDown(bool bottom)
{
    nweb_nweb_->PageDown(bottom);
}

void ArkWebNWebImpl::ScrollTo(float x, float y)
{
    nweb_nweb_->ScrollTo(x, y);
}

void ArkWebNWebImpl::ScrollBy(float delta_x, float delta_y)
{
    nweb_nweb_->ScrollBy(delta_x, delta_y);
}

void ArkWebNWebImpl::SlideScroll(float vx, float vy)
{
    nweb_nweb_->SlideScroll(vx, vy);
}

bool ArkWebNWebImpl::GetCertChainDerData(ArkWebStringVector& cert_chain_data, bool is_single_cert)
{
    std::vector<std::string> cert_chain_data_vector;
    bool result = nweb_nweb_->GetCertChainDerData(cert_chain_data_vector, is_single_cert);
    cert_chain_data = ArkWebStringVectorClassToStruct(cert_chain_data_vector);
    return result;
}

void ArkWebNWebImpl::SetScreenOffSet(double x, double y)
{
    nweb_nweb_->SetScreenOffSet(x, y);
}

void ArkWebNWebImpl::SetAudioMuted(bool muted)
{
    nweb_nweb_->SetAudioMuted(muted);
}

void ArkWebNWebImpl::SetShouldFrameSubmissionBeforeDraw(bool should)
{
    nweb_nweb_->SetShouldFrameSubmissionBeforeDraw(should);
}

void ArkWebNWebImpl::NotifyPopupWindowResult(bool result)
{
    nweb_nweb_->NotifyPopupWindowResult(result);
}

void ArkWebNWebImpl::SetAudioResumeInterval(int32_t resume_interval)
{
    nweb_nweb_->SetAudioResumeInterval(resume_interval);
}

void ArkWebNWebImpl::SetAudioExclusive(bool audio_exclusive)
{
    nweb_nweb_->SetAudioExclusive(audio_exclusive);
}

void ArkWebNWebImpl::RegisterScreenLockFunction(int32_t window_id, ArkWebRefPtr<ArkWebScreenLockCallback> callback)
{
    if (CHECK_REF_PTR_IS_NULL(callback)) {
        nweb_nweb_->RegisterScreenLockFunction(window_id, nullptr);
        return;
    }

    nweb_nweb_->RegisterScreenLockFunction(window_id, std::make_shared<ArkWebScreenLockCallbackWrapper>(callback));
}

void ArkWebNWebImpl::UnRegisterScreenLockFunction(int32_t window_id)
{
    nweb_nweb_->UnRegisterScreenLockFunction(window_id);
}

void ArkWebNWebImpl::NotifyMemoryLevel(int32_t level)
{
    nweb_nweb_->NotifyMemoryLevel(level);
}

void ArkWebNWebImpl::OnWebviewHide()
{
    nweb_nweb_->OnWebviewHide();
}

void ArkWebNWebImpl::OnWebviewShow()
{
    nweb_nweb_->OnWebviewShow();
}

ArkWebRefPtr<ArkWebDragData> ArkWebNWebImpl::GetOrCreateDragData()
{
    std::shared_ptr<OHOS::NWeb::NWebDragData> nweb_drag_data = nweb_nweb_->GetOrCreateDragData();
    if (CHECK_SHARED_PTR_IS_NULL(nweb_drag_data)) {
        return nullptr;
    }

    return new ArkWebDragDataImpl(nweb_drag_data);
}

void ArkWebNWebImpl::PrefetchPage(const ArkWebString& url, const ArkWebStringMap& additional_http_headers)
{
    nweb_nweb_->PrefetchPage(ArkWebStringStructToClass(url), ArkWebStringMapStructToClass(additional_http_headers));
}

void ArkWebNWebImpl::SetWindowId(uint32_t window_id)
{
    nweb_nweb_->SetWindowId(window_id);
}

void ArkWebNWebImpl::OnOccluded()
{
    nweb_nweb_->OnOccluded();
}

void ArkWebNWebImpl::OnUnoccluded()
{
    nweb_nweb_->OnUnoccluded();
}

void ArkWebNWebImpl::SetToken(void* token)
{
    nweb_nweb_->SetToken(token);
}

void ArkWebNWebImpl::SetNestedScrollMode(const int32_t& nested_scroll_mode)
{
    nweb_nweb_->SetNestedScrollMode(static_cast<ArkWebNestedScrollMode>(nested_scroll_mode));
}

void ArkWebNWebImpl::SetEnableLowerFrameRate(bool enabled)
{
    nweb_nweb_->SetEnableLowerFrameRate(enabled);
}

void ArkWebNWebImpl::SetVirtualKeyBoardArg(int32_t width, int32_t height, double keyboard)
{
    nweb_nweb_->SetVirtualKeyBoardArg(width, height, keyboard);
}

bool ArkWebNWebImpl::ShouldVirtualKeyboardOverlay()
{
    return nweb_nweb_->ShouldVirtualKeyboardOverlay();
}

void ArkWebNWebImpl::SetDrawRect(int32_t x, int32_t y, int32_t width, int32_t height)
{
    nweb_nweb_->SetDrawRect(x, y, width, height);
}

void ArkWebNWebImpl::SetDrawMode(int32_t mode)
{
    nweb_nweb_->SetDrawMode(mode);
}

void* ArkWebNWebImpl::CreateWebPrintDocumentAdapter(const ArkWebString& job_name)
{
    return nweb_nweb_->CreateWebPrintDocumentAdapter(ArkWebStringStructToClass(job_name));
}

int ArkWebNWebImpl::PostUrl(const ArkWebString& url, const ArkWebCharVector& post_data)
{
    return nweb_nweb_->PostUrl(
        ArkWebStringStructToClass(url), ArkWebBasicVectorStructToClass<char, ArkWebCharVector>(post_data));
}

void ArkWebNWebImpl::JavaScriptOnDocumentStart(const ArkWebStringVectorMap& script_items)
{
    nweb_nweb_->JavaScriptOnDocumentStart(ArkWebStringVectorMapStructToClass(script_items));
}

void ArkWebNWebImpl::ExecuteAction(int64_t accessibility_id, uint32_t action)
{
    nweb_nweb_->ExecuteAction(accessibility_id, action);
}

ArkWebRefPtr<ArkWebAccessibilityNodeInfo> ArkWebNWebImpl::GetFocusedAccessibilityNodeInfo(
    int64_t accessibility_id, bool is_accessibility_focus)
{
    std::shared_ptr<OHOS::NWeb::NWebAccessibilityNodeInfo> nweb_accessibility_node_info =
        nweb_nweb_->GetFocusedAccessibilityNodeInfo(accessibility_id, is_accessibility_focus);
    if (CHECK_SHARED_PTR_IS_NULL(nweb_accessibility_node_info)) {
        return nullptr;
    }

    return new ArkWebAccessibilityNodeInfoImpl(nweb_accessibility_node_info);
}

ArkWebRefPtr<ArkWebAccessibilityNodeInfo> ArkWebNWebImpl::GetAccessibilityNodeInfoById(int64_t accessibility_id)
{
    std::shared_ptr<OHOS::NWeb::NWebAccessibilityNodeInfo> nweb_accessibility_node_info =
        nweb_nweb_->GetAccessibilityNodeInfoById(accessibility_id);
    if (CHECK_SHARED_PTR_IS_NULL(nweb_accessibility_node_info)) {
        return nullptr;
    }

    return new ArkWebAccessibilityNodeInfoImpl(nweb_accessibility_node_info);
}

ArkWebRefPtr<ArkWebAccessibilityNodeInfo> ArkWebNWebImpl::GetAccessibilityNodeInfoByFocusMove(
    int64_t accessibility_id, int32_t direction)
{
    std::shared_ptr<OHOS::NWeb::NWebAccessibilityNodeInfo> nweb_accessibility_node_info =
        nweb_nweb_->GetAccessibilityNodeInfoByFocusMove(accessibility_id, direction);
    if (CHECK_SHARED_PTR_IS_NULL(nweb_accessibility_node_info)) {
        return nullptr;
    }

    return new ArkWebAccessibilityNodeInfoImpl(nweb_accessibility_node_info);
}

void ArkWebNWebImpl::SetAccessibilityState(bool state)
{
    nweb_nweb_->SetAccessibilityState(state);
}

bool ArkWebNWebImpl::NeedSoftKeyboard()
{
    return nweb_nweb_->NeedSoftKeyboard();
}

bool ArkWebNWebImpl::Discard()
{
    return nweb_nweb_->Discard();
}

bool ArkWebNWebImpl::Restore()
{
    return nweb_nweb_->Restore();
}

int ArkWebNWebImpl::GetSecurityLevel()
{
    return nweb_nweb_->GetSecurityLevel();
}

void ArkWebNWebImpl::CallH5Function(
    int32_t routingId, int32_t h5ObjectId, const ArkWebString& h5MethodName, const ArkWebValueVector& args)
{
    nweb_nweb_->CallH5Function(
        routingId, h5ObjectId, ArkWebStringStructToClass(h5MethodName), ArkWebValueVectorStructToClass(args));
}

bool ArkWebNWebImpl::IsIncognitoMode()
{
    return nweb_nweb_->IsIncognitoMode();
}

void ArkWebNWebImpl::RegisterNativeArkJSFunction(const char* objName, const ArkWebJsProxyCallbackVector& callbacks)
{
    nweb_nweb_->RegisterNativeArkJSFunction(objName, ArkWebJsProxyCallbackVectorStructToClass(callbacks));
}

void ArkWebNWebImpl::UnRegisterNativeArkJSFunction(const char* objName)
{
    nweb_nweb_->UnRegisterNativeArkJSFunction(objName);
}

void ArkWebNWebImpl::RegisterNativeValideCallback(const char* webName, const NativeArkWebOnValidCallback callback)
{
    nweb_nweb_->RegisterNativeValideCallback(webName, callback);
}

void ArkWebNWebImpl::RegisterNativeDestroyCallback(const char* webName, const NativeArkWebOnValidCallback callback)
{
    nweb_nweb_->RegisterNativeDestroyCallback(webName, callback);
}

void ArkWebNWebImpl::JavaScriptOnDocumentEnd(const ArkWebStringVectorMap& script_items)
{
    nweb_nweb_->JavaScriptOnDocumentEnd(ArkWebStringVectorMapStructToClass(script_items));
}

void ArkWebNWebImpl::EnableSafeBrowsing(bool enable)
{
    nweb_nweb_->EnableSafeBrowsing(enable);
}

bool ArkWebNWebImpl::IsSafeBrowsingEnabled()
{
    return nweb_nweb_->IsSafeBrowsingEnabled();
}

void ArkWebNWebImpl::SetPrintBackground(bool enable)
{
    nweb_nweb_->SetPrintBackground(enable);
}

bool ArkWebNWebImpl::GetPrintBackground()
{
    return nweb_nweb_->GetPrintBackground();
}

void ArkWebNWebImpl::CloseAllMediaPresentations()
{
    nweb_nweb_->CloseAllMediaPresentations();
}

void ArkWebNWebImpl::StopAllMedia()
{
    nweb_nweb_->StopAllMedia();
}

void ArkWebNWebImpl::ResumeAllMedia()
{
    nweb_nweb_->ResumeAllMedia();
}

void ArkWebNWebImpl::PauseAllMedia()
{
    nweb_nweb_->PauseAllMedia();
}

int ArkWebNWebImpl::GetMediaPlaybackState()
{
    return nweb_nweb_->GetMediaPlaybackState();
}

ArkWebString ArkWebNWebImpl::GetLastJavascriptProxyCallingFrameUrl()
{
    return ArkWebStringClassToStruct(nweb_nweb_->GetLastJavascriptProxyCallingFrameUrl());
}

void ArkWebNWebImpl::EnableIntelligentTrackingPrevention(bool enable)
{
    nweb_nweb_->EnableIntelligentTrackingPrevention(enable);
}

bool ArkWebNWebImpl::IsIntelligentTrackingPreventionEnabled()
{
    return nweb_nweb_->IsIntelligentTrackingPreventionEnabled();
}

void ArkWebNWebImpl::StartCamera()
{
    nweb_nweb_->StartCamera();
}

void ArkWebNWebImpl::StopCamera()
{
    nweb_nweb_->StopCamera();
}

void ArkWebNWebImpl::CloseCamera()
{
    nweb_nweb_->CloseCamera();
}

bool ArkWebNWebImpl::GetPendingSizeStatus()
{
    return nweb_nweb_->GetPendingSizeStatus();
}

void ArkWebNWebImpl::ScrollByRefScreen(float delta_x, float delta_y, float vx, float vy)
{
    nweb_nweb_->ScrollByRefScreen(delta_x, delta_y, vx, vy);
}

void ArkWebNWebImpl::ExecuteJavaScriptExt(
    const int fd, const size_t scriptLength, ArkWebRefPtr<ArkWebMessageValueCallback> callback, bool extention)
{
    if (CHECK_REF_PTR_IS_NULL(callback)) {
        nweb_nweb_->ExecuteJavaScriptExt(fd, scriptLength, nullptr, extention);
        return;
    }

    nweb_nweb_->ExecuteJavaScriptExt(
        fd, scriptLength, std::make_shared<ArkWebMessageValueCallbackWrapper>(callback), extention);
}

void ArkWebNWebImpl::OnRenderToBackground()
{
    nweb_nweb_->OnRenderToBackground();
}

void ArkWebNWebImpl::OnRenderToForeground()
{
    nweb_nweb_->OnRenderToForeground();
}

void ArkWebNWebImpl::OnOnlineRenderToForeground()
{
    nweb_nweb_->OnOnlineRenderToForeground();
}

void ArkWebNWebImpl::PrecompileJavaScript(const ArkWebString& url, const ArkWebString& script,
    ArkWebRefPtr<ArkWebCacheOptions>& cacheOptions, ArkWebRefPtr<ArkWebMessageValueCallback> callback)
{
    std::shared_ptr<OHOS::NWeb::CacheOptions> options = std::make_shared<ArkWebCacheOptionsWrapper>(cacheOptions);
    nweb_nweb_->PrecompileJavaScript(ArkWebStringStructToClass(url), ArkWebStringStructToClass(script), options,
        std::make_shared<ArkWebMessageValueCallbackWrapper>(callback));
}

void ArkWebNWebImpl::OnCreateNativeMediaPlayer(ArkWebRefPtr<ArkWebCreateNativeMediaPlayerCallback> callback)
{
    if (CHECK_REF_PTR_IS_NULL(callback)) {
        nweb_nweb_->OnCreateNativeMediaPlayer(nullptr);
        return;
    }

    nweb_nweb_->OnCreateNativeMediaPlayer(std::make_shared<ArkWebCreateNativeMediaPlayerCallbackWrapper>(callback));
}

void ArkWebNWebImpl::DragResize(uint32_t width, uint32_t height, uint32_t pre_height, uint32_t pre_width)
{
    nweb_nweb_->DragResize(width, height, pre_height, pre_width);
}

void ArkWebNWebImpl::OnTouchCancelById(int32_t id, double x, double y, bool from_overlay)
{
    nweb_nweb_->OnTouchCancelById(id, x, y, from_overlay);
}

int ArkWebNWebImpl::ScaleGestureChange(double scale, double centerX, double centerY)
{
    return nweb_nweb_->ScaleGestureChange(scale, centerX, centerY);
}

void ArkWebNWebImpl::InjectOfflineResource(const ArkWebString& url, const ArkWebString& origin,
    const ArkWebUint8Vector& resource, const ArkWebStringMap& responseHeaders, const int type)
{
    nweb_nweb_->InjectOfflineResource(ArkWebStringStructToClass(url), ArkWebStringStructToClass(origin),
        ArkWebBasicVectorStructToClass<uint8_t, ArkWebUint8Vector>(resource),
        ArkWebStringMapStructToClass(responseHeaders), type);
}

bool ArkWebNWebImpl::TerminateRenderProcess()
{
    return nweb_nweb_->TerminateRenderProcess();
}

void ArkWebNWebImpl::SuggestionSelected(int32_t index)
{
    nweb_nweb_->SuggestionSelected(index);
}

void ArkWebNWebImpl::SendTouchpadFlingEvent(double x, double y, double vx, double vy)
{
    nweb_nweb_->SendTouchpadFlingEvent(x, y, vx, vy);
}

void ArkWebNWebImpl::RegisterArkJSfunction(const ArkWebString& object_name, const ArkWebStringVector& method_list,
    const ArkWebStringVector& async_method_list, const int32_t object_id)
{
    nweb_nweb_->RegisterArkJSfunction(ArkWebStringStructToClass(object_name),
        ArkWebStringVectorStructToClass(method_list), ArkWebStringVectorStructToClass(async_method_list), object_id);
}

void ArkWebNWebImpl::SetFitContentMode(int32_t mode)
{
    nweb_nweb_->SetFitContentMode(mode);
}

ArkWebString ArkWebNWebImpl::GetSelectInfo()
{
    return ArkWebStringClassToStruct(nweb_nweb_->GetSelectInfo());
}

void ArkWebNWebImpl::OnSafeInsetsChange(int left, int top, int right, int bottom)
{
    nweb_nweb_->OnSafeInsetsChange(left, top, right, bottom);
}

void ArkWebNWebImpl::OnTextSelected()
{
    nweb_nweb_->OnTextSelected();
}

bool ArkWebNWebImpl::WebSendKeyEvent(int32_t key_code, int32_t key_action,
                                     const ArkWebInt32Vector& pressedCodes)
{
    return nweb_nweb_->WebSendKeyEvent(key_code, key_action,
        ArkWebBasicVectorStructToClass<int32_t, ArkWebInt32Vector>(pressedCodes));
}

void ArkWebNWebImpl::OnConfigurationUpdated(
    ArkWebRefPtr<ArkWebSystemConfiguration> configuration)
{
    if (CHECK_REF_PTR_IS_NULL(configuration)) {
        nweb_nweb_->OnConfigurationUpdated(nullptr);
        return;
    }
    nweb_nweb_->OnConfigurationUpdated(
        std::make_shared<ArkWebSystemConfigurationWrapper>(configuration));
}
void ArkWebNWebImpl::EnableAdsBlock(bool enable) {
    nweb_nweb_->EnableAdsBlock(enable);
}

bool ArkWebNWebImpl::IsAdsBlockEnabled() {
    return nweb_nweb_->IsAdsBlockEnabled();
}

bool ArkWebNWebImpl::IsAdsBlockEnabledForCurPage() {
    return nweb_nweb_->IsAdsBlockEnabledForCurPage();
}

void ArkWebNWebImpl::NotifyForNextTouchEvent()
{
    nweb_nweb_->NotifyForNextTouchEvent();
}

int ArkWebNWebImpl::SetUrlTrustList(const ArkWebString& urlTrustList)
{
    return nweb_nweb_->SetUrlTrustList(ArkWebStringStructToClass(urlTrustList));
}

void ArkWebNWebImpl::PutSpanstringConvertHtmlCallback(
    ArkWebRefPtr<ArkWebSpanstringConvertHtmlCallback> callback) {
    if (CHECK_REF_PTR_IS_NULL(callback)) {
        nweb_nweb_->PutSpanstringConvertHtmlCallback(nullptr);
        return;
    }
    nweb_nweb_->PutSpanstringConvertHtmlCallback(
        std::make_shared<ArkWebSpanstringConvertHtmlCallbackWrapper>(callback));
}
} // namespace OHOS::ArkWeb
