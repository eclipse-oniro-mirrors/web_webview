/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "webview_controller.h"

#include <memory>
#include <unordered_map>
#include <securec.h>
#include <regex>

#include "application_context.h"
#include "business_error.h"
#include "napi_parse_utils.h"
#include "nweb_napi_scope.h"
#include "ohos_resource_adapter_impl.h"

#include "native_arkweb_utils.h"
#include "native_interface_arkweb.h"
#include "native_media_player_impl.h"

#include "nweb_log.h"
#include "nweb_store_web_archive_callback.h"
#include "web_errors.h"
#include "webview_createpdf_execute_callback.h"
#include "webview_hasimage_callback.h"
#include "webview_javascript_execute_callback.h"
#include "webview_javascript_result_callback.h"

#include "nweb_precompile_callback.h"
#include "nweb_cache_options_impl.h"

#include "bundle_mgr_proxy.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "parameters.h"
#include "system_ability_definition.h"
#include "../../../../ohos_interface/ohos_glue/base/include/ark_web_errno.h"

namespace {
constexpr int32_t PARAMZERO = 0;
constexpr int32_t PARAMONE = 1;
constexpr int32_t RESULT_COUNT = 2;
const std::string BUNDLE_NAME_PREFIX = "bundleName:";
const std::string MODULE_NAME_PREFIX = "moduleName:";
} // namespace

namespace OHOS {
namespace NWeb {
namespace {
constexpr uint32_t URL_MAXIMUM = 2048;
const std::string EVENT_CONTROLLER_ATTACH_STATE_CHANGE = "controllerAttachStateChange";
const std::string EVENT_WAIT_FOR_ATTACH = "waitForAttach";

struct WaitForAttachParam {
    napi_async_work asyncWork;
    napi_deferred deferred;
    int32_t timeout;
    WebviewController* webviewController;
    int32_t state;
};

bool GetAppBundleNameAndModuleName(std::string& bundleName, std::string& moduleName)
{
    static std::string applicationBundleName;
    static std::string applicationModuleName;
    if (!applicationBundleName.empty() && !applicationModuleName.empty()) {
        bundleName = applicationBundleName;
        moduleName = applicationModuleName;
        return true;
    }
    std::shared_ptr<AbilityRuntime::ApplicationContext> context =
        AbilityRuntime::ApplicationContext::GetApplicationContext();
    if (!context) {
        WVLOG_E("Failed to get application context.");
        return false;
    }
    auto resourceManager = context->GetResourceManager();
    if (!resourceManager) {
        WVLOG_E("Failed to get resource manager.");
        return false;
    }
    applicationBundleName = resourceManager->bundleInfo.first;
    applicationModuleName = resourceManager->bundleInfo.second;
    bundleName = applicationBundleName;
    moduleName = applicationModuleName;
    WVLOG_D("application bundleName: %{public}s, moduleName: %{public}s", bundleName.c_str(), moduleName.c_str());
    return true;
}
}
using namespace NWebError;
std::mutex g_objectMtx;
std::unordered_map<int32_t, WebviewController*> g_webview_controller_map;
std::string WebviewController::customeSchemeCmdLine_ = "";
bool WebviewController::existNweb_ = false;
bool WebviewController::webDebuggingAccess_ = OHOS::system::GetBoolParameter("web.debug.devtools", false);
int32_t WebviewController::webDebuggingPort_ = 0;
std::set<std::string> WebviewController::webTagSet_;
int32_t WebviewController::webTagStrId_ = 0;
std::map<std::string, WebSchemeHandler*> WebviewController::webServiceWorkerSchemeHandlerMap_;

WebviewController::WebviewController(int32_t nwebId) : nwebId_(nwebId)
{
    if (IsInit()) {
        std::unique_lock<std::mutex> lk(g_objectMtx);
        g_webview_controller_map.emplace(nwebId, this);
    }
}

WebviewController::WebviewController(const std::string& webTag) : webTag_(webTag)
{
    NWebHelper::Instance().SetWebTag(-1, webTag_.c_str());
}

WebviewController::~WebviewController()
{
    std::unique_lock<std::mutex> lk(g_objectMtx);
    g_webview_controller_map.erase(nwebId_);

    {
        std::unique_lock<std::mutex> attachLock(attachMtx_);
        attachState_ = AttachState::ATTACHED;
        attachCond_.notify_all();
    }

    for (auto& [eventName, regObjs] : attachEventRegisterInfo_) {
        for (auto& regObj : regObjs) {
            if (regObj.m_regHanderRef != nullptr) {
                napi_delete_reference(regObj.m_regEnv, regObj.m_regHanderRef);
                regObj.m_regHanderRef = nullptr;
            }
        }
    }
    attachEventRegisterInfo_.clear();
}

void WebviewController::TriggerStateChangeCallback(const std::string& type)
{
    auto iter = attachEventRegisterInfo_.find(type);
    if (iter == attachEventRegisterInfo_.end()) {
        WVLOG_D("WebviewController::TriggerStateChangeCallback event %{public}s not found.",
            type.c_str());
        return;
    }

    const std::vector<WebRegObj>& regObjs = iter->second;
    for (const auto& regObj : regObjs) {
        if (!regObj.m_isMarked){
            napi_env env = regObj.m_regEnv;
            napi_value handler = nullptr;
            napi_get_reference_value(env, regObj.m_regHanderRef, &handler);

            if (handler == nullptr) {
                WVLOG_E("handler for event %{public}s is null.", type.c_str());
                continue;
            }

            napi_value jsState = nullptr;
            napi_create_int32(env, static_cast<int32_t>(attachState_), &jsState);

            napi_value undefined;
            napi_get_undefined(env, &undefined);

            napi_call_function(env, nullptr, handler, 1, &jsState, &undefined);
        }
    }
    for (auto it = iter->second.begin(); it != iter->second.end();) {
        if (it->m_isMarked) {
            napi_delete_reference(it->m_regEnv, it->m_regHanderRef);
            it = iter->second.erase(it);
        } else {
            ++it;
        }
    }
}

void WebviewController::SetWebId(int32_t nwebId)
{
    nwebId_ = nwebId;
    std::unique_lock<std::mutex> lk(g_objectMtx);
    g_webview_controller_map.emplace(nwebId, this);

    if (webTag_.empty()) {
        WVLOG_I("native webtag is empty, don't care because it's not a native instance");
        return;
    }

    AttachState prevState = attachState_;
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        OH_NativeArkWeb_BindWebTagToWebInstance(webTag_.c_str(), nweb_ptr);
        NWebHelper::Instance().SetWebTag(nwebId_, webTag_.c_str());
        {
            std::unique_lock<std::mutex> attachLock(attachMtx_);
            attachState_ = AttachState::ATTACHED;
            attachCond_.notify_all();
        }
        if (prevState != attachState_) {
            TriggerStateChangeCallback(EVENT_CONTROLLER_ATTACH_STATE_CHANGE);
        }
    }
    SetNWebJavaScriptResultCallBack();
    NativeArkWeb_OnValidCallback validCallback = OH_NativeArkWeb_GetJavaScriptProxyValidCallback(webTag_.c_str());
    if (validCallback) {
        WVLOG_I("native validCallback start to call");
        (*validCallback)(webTag_.c_str());
    } else {
        WVLOG_W("native validCallback is null, callback nothing");
    }
}

void WebviewController::SetWebDetach(int32_t nwebId)
{
    if (nwebId != nwebId_) {
        WVLOG_W("web detach nwebId is not equal, detach is %{public}d, current is %{public}d", nwebId, nwebId_);
        return;
    }

    if (attachState_ != AttachState::NOT_ATTACHED) {
        attachState_ = AttachState::NOT_ATTACHED;
        TriggerStateChangeCallback(EVENT_CONTROLLER_ATTACH_STATE_CHANGE);
    }
}

WebviewController* WebviewController::FromID(int32_t nwebId)
{
    std::unique_lock<std::mutex> lk(g_objectMtx);
    if (auto it = g_webview_controller_map.find(nwebId); it != g_webview_controller_map.end()) {
        auto control = it->second;
        return control;
    }
    return nullptr;
}

void WebviewController::InnerCompleteWindowNew(int32_t parentNwebId)
{
    WVLOG_D("WebviewController::InnerCompleteWindowNew parentNwebId == "
            "%{public}d ",
        parentNwebId);
    if (parentNwebId < 0) {
        WVLOG_E("WebviewController::InnerCompleteWindowNew parentNwebId == %{public}d "
                "error",
            parentNwebId);
        return;
    }
    auto parentControl = FromID(parentNwebId);
    if (!parentControl || !(parentControl->javaScriptResultCb_)) {
        WVLOG_E("WebviewController::InnerCompleteWindowNew parentControl or "
                "javaScriptResultCb_ is null");
        return;
    }

    auto parNamedObjs = parentControl->javaScriptResultCb_->GetNamedObjects();

    auto currentControl = FromID(nwebId_);
    if (!currentControl || !(currentControl->javaScriptResultCb_)) {
        WVLOG_E("WebviewController::InnerCompleteWindowNew currentControl or "
                "javaScriptResultCb_ is null");
        return;
    }

    std::unique_lock<std::mutex> lock(webMtx_);
    {
        auto curNamedObjs = currentControl->javaScriptResultCb_->GetNamedObjects();
        SetNWebJavaScriptResultCallBack();
        for (auto it = parNamedObjs.begin(); it != parNamedObjs.end(); it++) {
            if (curNamedObjs.find(it->first) != curNamedObjs.end()) {
                continue;
            }
            if (it->second && IsInit()) {
                RegisterJavaScriptProxyParam param;
                param.env = it->second->GetEnv();
                param.obj = it->second->GetValue();
                param.objName = it->first;
                param.syncMethodList = it->second->GetSyncMethodNames();
                param.asyncMethodList = it->second->GetAsyncMethodNames();
                param.permission = it->second->GetPermission();
                RegisterJavaScriptProxy(param);
            }
        }
    }
}

bool WebviewController::IsInit() const
{
    return NWebHelper::Instance().GetNWeb(nwebId_) ? true : false;
}

bool WebviewController::AccessForward() const
{
    bool access = false;
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        access = nweb_ptr->IsNavigateForwardAllowed();
    } else {
        WVLOG_E("WebviewController::AccessForward nweb_ptr is null");
    }
    return access;
}

bool WebviewController::AccessBackward() const
{
    bool access = false;
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        access = nweb_ptr->IsNavigatebackwardAllowed();
    }
    return access;
}

bool WebviewController::AccessStep(int32_t step) const
{
    bool access = false;
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        access = nweb_ptr->CanNavigateBackOrForward(step);
    }
    return access;
}

void WebviewController::ClearHistory()
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        nweb_ptr->DeleteNavigateHistory();
    }
}

void WebviewController::Forward()
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        nweb_ptr->NavigateForward();
    }
}

void WebviewController::Backward()
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        nweb_ptr->NavigateBack();
    }
}

void WebviewController::OnActive()
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        nweb_ptr->OnContinue();
    }
}

void WebviewController::OnInactive()
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        nweb_ptr->OnPause();
    }
}

void WebviewController::Refresh()
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        nweb_ptr->Reload();
    }
}

ErrCode WebviewController::ZoomIn()
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return INIT_ERROR;
    }
    ErrCode result = NWebError::NO_ERROR;
    result = nweb_ptr->ZoomIn();

    return result;
}

ErrCode WebviewController::ZoomOut()
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return INIT_ERROR;
    }
    ErrCode result = NWebError::NO_ERROR;
    result = nweb_ptr->ZoomOut();

    return result;
}

int32_t WebviewController::GetWebId() const
{
    int32_t webId = -1;
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        webId = static_cast<int32_t>(nweb_ptr->GetWebId());
    }
    return webId;
}

std::string WebviewController::GetUserAgent()
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return "";
    }
    std::shared_ptr<OHOS::NWeb::NWebPreference> setting = nweb_ptr->GetPreference();
    if (!setting) {
        return "";
    }
    return setting->DefaultUserAgent();
}

std::string WebviewController::GetCustomUserAgent() const
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return "";
    }
    std::shared_ptr<OHOS::NWeb::NWebPreference> setting = nweb_ptr->GetPreference();
    if (!setting) {
        return "";
    }
    return setting->UserAgent();
}

ErrCode WebviewController::SetCustomUserAgent(const std::string& userAgent)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return NWebError::INIT_ERROR;
    }
    std::shared_ptr<OHOS::NWeb::NWebPreference> setting = nweb_ptr->GetPreference();
    if (!setting) {
        return NWebError::INIT_ERROR;
    }
    setting->PutUserAgent(userAgent);
    return NWebError::NO_ERROR;
}

std::string WebviewController::GetTitle()
{
    std::string title = "";
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        title = nweb_ptr->Title();
    }
    return title;
}

int32_t WebviewController::GetProgress()
{
    int32_t progress = 0;
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        progress = nweb_ptr->PageLoadProgress();
    }
    return progress;
}

int32_t WebviewController::GetPageHeight()
{
    int32_t pageHeight = 0;
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        pageHeight = nweb_ptr->ContentHeight();
    }
    return pageHeight;
}

ErrCode WebviewController::BackOrForward(int32_t step)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return INIT_ERROR;
    }

    nweb_ptr->NavigateBackOrForward(step);
    return NWebError::NO_ERROR;
}

void WebviewController::StoreWebArchiveCallback(const std::string &baseName, bool autoName, napi_env env,
    napi_ref jsCallback)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        napi_value setResult[RESULT_COUNT] = {0};
        setResult[PARAMZERO] = BusinessError::CreateError(env, NWebError::INIT_ERROR);
        napi_get_null(env, &setResult[PARAMONE]);

        napi_value args[RESULT_COUNT] = {setResult[PARAMZERO], setResult[PARAMONE]};
        napi_value callback = nullptr;
        napi_get_reference_value(env, jsCallback, &callback);
        napi_value callbackResult = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, args, &callbackResult);
        napi_delete_reference(env, jsCallback);
        return;
    }

    if (jsCallback == nullptr) {
        return;
    }

    auto callbackImpl = std::make_shared<OHOS::NWeb::NWebStoreWebArchiveCallback>();
    callbackImpl->SetCallBack([env, jCallback = std::move(jsCallback)](std::string result) {
        if (!env) {
            return;
        }
        NApiScope scope(env);
        if (!scope.IsVaild()) {
            return;
        }

        napi_value setResult[RESULT_COUNT] = {0};
        if (result.empty()) {
            setResult[PARAMZERO] = BusinessError::CreateError(env, NWebError::INVALID_RESOURCE);
            napi_get_null(env, &setResult[PARAMONE]);
        } else {
            napi_get_undefined(env, &setResult[PARAMZERO]);
            napi_create_string_utf8(env, result.c_str(), NAPI_AUTO_LENGTH, &setResult[PARAMONE]);
        }
        napi_value args[RESULT_COUNT] = {setResult[PARAMZERO], setResult[PARAMONE]};
        napi_value callback = nullptr;
        napi_get_reference_value(env, jCallback, &callback);
        napi_value callbackResult = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, args, &callbackResult);

        napi_delete_reference(env, jCallback);
    });
    nweb_ptr->StoreWebArchive(baseName, autoName, callbackImpl);
    return;
}

void WebviewController::StoreWebArchivePromise(const std::string &baseName, bool autoName, napi_env env,
    napi_deferred deferred)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        napi_value jsResult = nullptr;
        jsResult = NWebError::BusinessError::CreateError(env, NWebError::INIT_ERROR);
        napi_reject_deferred(env, deferred, jsResult);
        return;
    }

    if (deferred == nullptr) {
        return;
    }

    auto callbackImpl = std::make_shared<OHOS::NWeb::NWebStoreWebArchiveCallback>();
    callbackImpl->SetCallBack([env, deferred](std::string result) {
        if (!env) {
            return;
        }
        NApiScope scope(env);
        if (!scope.IsVaild()) {
            return;
        }

        napi_value setResult[RESULT_COUNT] = {0};
        setResult[PARAMZERO] = NWebError::BusinessError::CreateError(env, NWebError::INVALID_RESOURCE);
        napi_create_string_utf8(env, result.c_str(), NAPI_AUTO_LENGTH, &setResult[PARAMONE]);
        napi_value args[RESULT_COUNT] = {setResult[PARAMZERO], setResult[PARAMONE]};
        if (!result.empty()) {
            napi_resolve_deferred(env, deferred, args[PARAMONE]);
        } else {
            napi_reject_deferred(env, deferred, args[PARAMZERO]);
        }
    });
    nweb_ptr->StoreWebArchive(baseName, autoName, callbackImpl);
    return;
}

std::vector<std::string> WebviewController::CreateWebMessagePorts()
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        std::vector<std::string> empty;
        return empty;
    }

    return nweb_ptr->CreateWebMessagePorts();
}

ErrCode WebviewController::PostWebMessage(std::string& message, std::vector<std::string>& ports, std::string& targetUrl)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return INIT_ERROR;
    }

    nweb_ptr->PostWebMessage(message, ports, targetUrl);
    return NWebError::NO_ERROR;
}

WebMessagePort::WebMessagePort(int32_t nwebId, std::string& port, bool isExtentionType)
    : nwebId_(nwebId), portHandle_(port), isExtentionType_(isExtentionType)
{}

ErrCode WebMessagePort::ClosePort()
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return INIT_ERROR;
    }

    nweb_ptr->ClosePort(portHandle_);
    portHandle_.clear();
    return NWebError::NO_ERROR;
}

ErrCode WebMessagePort::PostPortMessage(std::shared_ptr<NWebMessage> data, std::shared_ptr<NWebRomValue> value)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return INIT_ERROR;
    }

    if (portHandle_.empty()) {
        WVLOG_E("can't post message, message port already closed");
        return CAN_NOT_POST_MESSAGE;
    }
    nweb_ptr->PostPortMessageV2(portHandle_, value);
    if (ArkWebGetErrno() != RESULT_OK) {
        nweb_ptr->PostPortMessage(portHandle_, data);
    }
    return NWebError::NO_ERROR;
}

ErrCode WebMessagePort::SetPortMessageCallback(
    std::shared_ptr<NWebMessageValueCallback> callback)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return INIT_ERROR;
    }

    if (portHandle_.empty()) {
        WVLOG_E("can't register message port callback event, message port already closed");
        return CAN_NOT_REGISTER_MESSAGE_EVENT;
    }
    nweb_ptr->SetPortMessageCallback(portHandle_, callback);
    return NWebError::NO_ERROR;
}

std::string WebMessagePort::GetPortHandle() const
{
    return portHandle_;
}

std::shared_ptr<HitTestResult> WebviewController::GetHitTestValue()
{
    std::shared_ptr<HitTestResult> nwebResult;
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        nwebResult = nweb_ptr->GetHitTestResult();
        if (nwebResult) {
            nwebResult->SetType(ConverToWebHitTestType(nwebResult->GetType()));
        }
    }
    return nwebResult;
}

void WebviewController::RequestFocus()
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        nweb_ptr->OnFocus();
    }
}

std::string WebviewController::GenerateWebTag()
{
    std::string webTag = "arkweb:" + std::to_string(WebviewController::webTagStrId_);
    while (WebviewController::webTagSet_.find(webTag) != WebviewController::webTagSet_.end()) {
        WebviewController::webTagStrId_++;
        webTag = "arkweb:" + std::to_string(WebviewController::webTagStrId_);
    }
    return webTag;
}

bool WebviewController::GetRawFileUrl(const std::string &fileName,
    const std::string& bundleName, const std::string& moduleName, std::string &result) const
{
    if (fileName.empty()) {
        WVLOG_E("File name is empty.");
        return false;
    }
    if (hapPath_.empty()) {
        std::shared_ptr<AbilityRuntime::ApplicationContext> context =
            AbilityRuntime::ApplicationContext::GetApplicationContext();
        std::string packagePath = "file:///" + context->GetBundleCodeDir() + "/";
        std::string contextBundleName = context->GetBundleName() + "/";
        std::shared_ptr<AppExecFwk::ApplicationInfo> appInfo = context->GetApplicationInfo();
        std::string entryDir = appInfo->entryDir;
        bool isStage = entryDir.find("entry") == std::string::npos ? false : true;
        result = isStage ? packagePath + "entry/resources/rawfile/" + fileName :
            packagePath + contextBundleName + "assets/entry/resources/rawfile/" + fileName;
    } else {
        std::string appBundleName;
        std::string appModuleName;
        result = "resource://RAWFILE/";
        if (!bundleName.empty() && !moduleName.empty() &&
            GetAppBundleNameAndModuleName(appBundleName, appModuleName)) {
            if (appBundleName != bundleName || appModuleName != moduleName) {
                result += BUNDLE_NAME_PREFIX + bundleName + "/" + MODULE_NAME_PREFIX + moduleName + "/";
            }
        }
        result += fileName;
    }
    WVLOG_D("The parsed url is: ***");
    return true;
}

bool WebviewController::ParseUrl(napi_env env, napi_value urlObj, std::string& result) const
{
    napi_valuetype valueType = napi_null;
    napi_typeof(env, urlObj, &valueType);
    if ((valueType != napi_object) && (valueType != napi_string)) {
        WVLOG_E("Unable to parse url object.");
        return false;
    }
    if (valueType == napi_string) {
        NapiParseUtils::ParseString(env, urlObj, result);
        WVLOG_D("The parsed url is: ***");
        return true;
    }
    napi_value type = nullptr;
    napi_valuetype typeVlueType = napi_null;
    napi_get_named_property(env, urlObj, "type", &type);
    napi_typeof(env, type, &typeVlueType);
    if (typeVlueType == napi_number) {
        int32_t typeInteger;
        NapiParseUtils::ParseInt32(env, type, typeInteger);
        if (typeInteger == static_cast<int>(ResourceType::RAWFILE)) {
            return ParseRawFileUrl(env, urlObj, result);
        } else if (typeInteger == static_cast<int>(ResourceType::STRING)) {
            if (!GetResourceUrl(env, urlObj, result)) {
                WVLOG_E("Unable to parse string from url object.");
                return false;
            }
            return true;
        }
        WVLOG_E("The type parsed from url object is not RAWFILE.");
        return false;
    }
    WVLOG_E("Unable to parse type from url object.");
    return false;
}

bool WebviewController::ParseRawFileUrl(napi_env env, napi_value urlObj, std::string& result) const
{
    napi_value paraArray = nullptr;
    napi_get_named_property(env, urlObj, "params", &paraArray);
    bool isArray = false;
    napi_is_array(env, paraArray, &isArray);
    if (!isArray) {
        WVLOG_E("Unable to parse parameter array from url object.");
        return false;
    }
    napi_value fileNameObj;
    napi_value bundleNameObj;
    napi_value moduleNameObj;
    std::string fileName;
    std::string bundleName;
    std::string moduleName;
    napi_get_element(env, paraArray, 0, &fileNameObj);
    napi_get_named_property(env, urlObj, "bundleName", &bundleNameObj);
    napi_get_named_property(env, urlObj, "moduleName", &moduleNameObj);
    NapiParseUtils::ParseString(env, fileNameObj, fileName);
    NapiParseUtils::ParseString(env, bundleNameObj, bundleName);
    NapiParseUtils::ParseString(env, moduleNameObj, moduleName);
    return GetRawFileUrl(fileName, bundleName, moduleName, result);
}

bool WebviewController::GetResourceUrl(napi_env env, napi_value urlObj, std::string& result) const
{
    napi_value resIdObj = nullptr;
    napi_value bundleNameObj = nullptr;
    napi_value moduleNameObj = nullptr;

    int32_t resId;
    std::string bundleName;
    std::string moduleName;

    if ((napi_get_named_property(env, urlObj, "id", &resIdObj) != napi_ok) ||
        (napi_get_named_property(env, urlObj, "bundleName", &bundleNameObj) != napi_ok) ||
        (napi_get_named_property(env, urlObj, "moduleName", &moduleNameObj) != napi_ok)) {
        return false;
    }

    if (!NapiParseUtils::ParseInt32(env, resIdObj, resId) ||
        !NapiParseUtils::ParseString(env, bundleNameObj, bundleName) ||
        !NapiParseUtils::ParseString(env, moduleNameObj, moduleName)) {
        return false;
    }

    if (OhosResourceAdapterImpl::GetResourceString(bundleName, moduleName, resId, result)) {
        return true;
    }
    return false;
}

ErrCode WebviewController::PostUrl(std::string& url, std::vector<char>& postData)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return INIT_ERROR;
    }
    return nweb_ptr->PostUrl(url, postData);
}

ErrCode WebviewController::LoadUrl(std::string url)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return INIT_ERROR;
    }
    return nweb_ptr->Load(url);
}

ErrCode WebviewController::LoadUrl(std::string url, std::map<std::string, std::string> httpHeaders)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return INIT_ERROR;
    }
    return nweb_ptr->Load(url, httpHeaders);
}

ErrCode WebviewController::LoadData(std::string data, std::string mimeType, std::string encoding,
    std::string baseUrl, std::string historyUrl)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return INIT_ERROR;
    }
    if (baseUrl.empty() && historyUrl.empty()) {
        return nweb_ptr->LoadWithData(data, mimeType, encoding);
    }
    return nweb_ptr->LoadWithDataAndBaseUrl(baseUrl, data, mimeType, encoding, historyUrl);
}

int WebviewController::ConverToWebHitTestType(int hitType)
{
    WebHitTestType webHitType;
    switch (hitType) {
        case HitTestResult::UNKNOWN_TYPE:
            webHitType = WebHitTestType::UNKNOWN;
            break;
        case HitTestResult::ANCHOR_TYPE:
            webHitType = WebHitTestType::HTTP;
            break;
        case HitTestResult::PHONE_TYPE:
            webHitType = WebHitTestType::PHONE;
            break;
        case HitTestResult::GEO_TYPE:
            webHitType = WebHitTestType::MAP;
            break;
        case HitTestResult::EMAIL_TYPE:
            webHitType = WebHitTestType::EMAIL;
            break;
        case HitTestResult::IMAGE_TYPE:
            webHitType = WebHitTestType::IMG;
            break;
        case HitTestResult::IMAGE_ANCHOR_TYPE:
            webHitType = WebHitTestType::HTTP_IMG;
            break;
        case HitTestResult::SRC_ANCHOR_TYPE:
            webHitType = WebHitTestType::HTTP;
            break;
        case HitTestResult::SRC_IMAGE_ANCHOR_TYPE:
            webHitType = WebHitTestType::HTTP_IMG;
            break;
        case HitTestResult::EDIT_TEXT_TYPE:
            webHitType = WebHitTestType::EDIT;
            break;
        default:
            webHitType = WebHitTestType::UNKNOWN;
            break;
    }
    return static_cast<int>(webHitType);
}

int WebviewController::GetHitTest()
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        std::shared_ptr<HitTestResult> nwebResult = nweb_ptr->GetHitTestResult();
        if (nwebResult) {
            return ConverToWebHitTestType(nwebResult->GetType());
        } else {
            return ConverToWebHitTestType(HitTestResult::UNKNOWN_TYPE);
        }
    }
    return static_cast<int>(WebHitTestType::UNKNOWN);
}


void WebviewController::ClearMatches()
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        nweb_ptr->ClearMatches();
    }
}

void WebviewController::SearchNext(bool forward)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        nweb_ptr->FindNext(forward);
    }
}

void WebviewController::EnableSafeBrowsing(bool enable)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        nweb_ptr->EnableSafeBrowsing(enable);
    }
}

bool WebviewController::IsSafeBrowsingEnabled() const
{
    bool isSafeBrowsingEnabled = false;
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        isSafeBrowsingEnabled = nweb_ptr->IsSafeBrowsingEnabled();
    }
    return isSafeBrowsingEnabled;
}

void WebviewController::SearchAllAsync(const std::string& searchString)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        nweb_ptr->FindAllAsync(searchString);
    }
}

void WebviewController::ClearSslCache()
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        nweb_ptr->ClearSslCache();
    }
}

void WebviewController::ClearClientAuthenticationCache()
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        nweb_ptr->ClearClientAuthenticationCache();
    }
}

void WebviewController::Stop()
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        nweb_ptr->Stop();
    }
}

ErrCode WebviewController::Zoom(float factor)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return INIT_ERROR;
    }
    ErrCode result = NWebError::NO_ERROR;
    result = nweb_ptr->Zoom(factor);

    return result;
}

ErrCode WebviewController::DeleteJavaScriptRegister(const std::string& objName,
    const std::vector<std::string>& methodList)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        nweb_ptr->UnregisterArkJSfunction(objName, methodList);
    }

    if (javaScriptResultCb_) {
        bool ret = javaScriptResultCb_->DeleteJavaScriptRegister(objName);
        if (!ret) {
            return CANNOT_DEL_JAVA_SCRIPT_PROXY;
        }
    }

    return NWebError::NO_ERROR;
}

void WebviewController::SetNWebJavaScriptResultCallBack()
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return;
    }

    if (javaScriptResultCb_ && (javaScriptResultCb_->GetNWebId() == nwebId_)) {
        return;
    }

    javaScriptResultCb_ = std::make_shared<WebviewJavaScriptResultCallBack>(nwebId_);
    nweb_ptr->SetNWebJavaScriptResultCallBack(javaScriptResultCb_);
}

void WebviewController::RegisterJavaScriptProxy(RegisterJavaScriptProxyParam& param)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        WVLOG_E("WebviewController::RegisterJavaScriptProxy nweb_ptr is null");
        return;
    }
    JavaScriptOb::ObjectID objId =
        static_cast<JavaScriptOb::ObjectID>(JavaScriptOb::JavaScriptObjIdErrorCode::WEBCONTROLLERERROR);

    if (!javaScriptResultCb_) {
        WVLOG_E("WebviewController::RegisterJavaScriptProxy javaScriptResultCb_ is "
                "null");
        return;
    }

    if (param.syncMethodList.empty() && param.asyncMethodList.empty()) {
        WVLOG_E("WebviewController::RegisterJavaScriptProxy all methodList are "
                "empty");
        return;
    }

    std::vector<std::string> allMethodList;
    std::merge(param.syncMethodList.begin(), param.syncMethodList.end(),
               param.asyncMethodList.begin(), param.asyncMethodList.end(),
               std::back_inserter(allMethodList));

    RegisterJavaScriptProxyParam param_tmp;
    param_tmp.env = param.env;
    param_tmp.obj = param.obj;
    param_tmp.objName = param.objName;
    param_tmp.syncMethodList = allMethodList;
    param_tmp.asyncMethodList = param.asyncMethodList;
    param_tmp.permission = param.permission;
    objId = javaScriptResultCb_->RegisterJavaScriptProxy(param_tmp);

    nweb_ptr->RegisterArkJSfunction(param_tmp.objName, param_tmp.syncMethodList,
                                    std::vector<std::string>(), objId, param_tmp.permission);
}

void WebviewController::RunJavaScriptCallback(
    const std::string& script, napi_env env, napi_ref jsCallback, bool extention)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        napi_value setResult[RESULT_COUNT] = {0};
        setResult[PARAMZERO] = BusinessError::CreateError(env, NWebError::INIT_ERROR);
        napi_get_null(env, &setResult[PARAMONE]);

        napi_value args[RESULT_COUNT] = {setResult[PARAMZERO], setResult[PARAMONE]};
        napi_value callback = nullptr;
        napi_get_reference_value(env, jsCallback, &callback);
        napi_value callbackResult = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, args, &callbackResult);
        napi_delete_reference(env, jsCallback);
        return;
    }

    if (jsCallback == nullptr) {
        return;
    }

    auto callbackImpl = std::make_shared<WebviewJavaScriptExecuteCallback>(env, jsCallback, nullptr, extention);
    nweb_ptr->ExecuteJavaScript(script, callbackImpl, extention);
}

void WebviewController::RunJavaScriptPromise(const std::string &script, napi_env env,
    napi_deferred deferred, bool extention)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        napi_value jsResult = nullptr;
        jsResult = NWebError::BusinessError::CreateError(env, NWebError::INIT_ERROR);
        napi_reject_deferred(env, deferred, jsResult);
        return;
    }

    if (deferred == nullptr) {
        return;
    }

    auto callbackImpl = std::make_shared<WebviewJavaScriptExecuteCallback>(env, nullptr, deferred, extention);
    nweb_ptr->ExecuteJavaScript(script, callbackImpl, extention);
}

void WebviewController::RunJavaScriptCallbackExt(
    const int fd, const size_t scriptLength, napi_env env, napi_ref jsCallback, bool extention)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        napi_value setResult[RESULT_COUNT] = {0};
        setResult[PARAMZERO] = BusinessError::CreateError(env, NWebError::INIT_ERROR);
        napi_get_null(env, &setResult[PARAMONE]);

        napi_value args[RESULT_COUNT] = {setResult[PARAMZERO], setResult[PARAMONE]};
        napi_value callback = nullptr;
        napi_get_reference_value(env, jsCallback, &callback);
        napi_value callbackResult = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, args, &callbackResult);
        napi_delete_reference(env, jsCallback);
        close(fd);
        return;
    }

    if (jsCallback == nullptr) {
        close(fd);
        return;
    }

    auto callbackImpl = std::make_shared<WebviewJavaScriptExecuteCallback>(env, jsCallback, nullptr, extention);
    nweb_ptr->ExecuteJavaScriptExt(fd, scriptLength, callbackImpl, extention);
}

void WebviewController::RunJavaScriptPromiseExt(
    const int fd, const size_t scriptLength, napi_env env, napi_deferred deferred, bool extention)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        napi_value jsResult = nullptr;
        jsResult = NWebError::BusinessError::CreateError(env, NWebError::INIT_ERROR);
        napi_reject_deferred(env, deferred, jsResult);
        close(fd);
        return;
    }

    if (deferred == nullptr) {
        close(fd);
        return;
    }

    auto callbackImpl = std::make_shared<WebviewJavaScriptExecuteCallback>(env, nullptr, deferred, extention);
    nweb_ptr->ExecuteJavaScriptExt(fd, scriptLength, callbackImpl, extention);
}

void WebviewController::CreatePDFCallbackExt(
    napi_env env, std::shared_ptr<NWebPDFConfigArgs> pdfConfig, napi_ref pdfCallback)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        napi_value setResult[RESULT_COUNT] = { 0 };
        setResult[PARAMZERO] = BusinessError::CreateError(env, NWebError::INIT_ERROR);
        napi_get_null(env, &setResult[PARAMONE]);

        napi_value args[RESULT_COUNT] = { setResult[PARAMZERO], setResult[PARAMONE] };
        napi_value callback = nullptr;
        napi_get_reference_value(env, pdfCallback, &callback);
        napi_value callbackResult = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, args, &callbackResult);
        napi_delete_reference(env, pdfCallback);
        return;
    }
    if (pdfCallback == nullptr) {
        return;
    }
    auto callbackImpl = std::make_shared<WebviewCreatePDFExecuteCallback>(env, pdfCallback, nullptr);
    nweb_ptr->ExecuteCreatePDFExt(pdfConfig, callbackImpl);
}

void WebviewController::CreatePDFPromiseExt(
    napi_env env, std::shared_ptr<NWebPDFConfigArgs> pdfConfig, napi_deferred deferred)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        napi_value pdfResult = nullptr;
        pdfResult = NWebError::BusinessError::CreateError(env, NWebError::INIT_ERROR);
        napi_reject_deferred(env, deferred, pdfResult);
        return;
    }
    if (deferred == nullptr) {
        return;
    }
    auto callbackImpl = std::make_shared<WebviewCreatePDFExecuteCallback>(env, nullptr, deferred);
    nweb_ptr->ExecuteCreatePDFExt(pdfConfig, callbackImpl);
}

std::string WebviewController::GetUrl()
{
    std::string url = "";
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        url = nweb_ptr->GetUrl();
    }
    return url;
}

std::string WebviewController::GetOriginalUrl()
{
    std::string url = "";
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        url = nweb_ptr->GetOriginalUrl();
    }
    return url;
}

bool WebviewController::TerminateRenderProcess() const
{
    bool ret = false;
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        ret = nweb_ptr->TerminateRenderProcess();
    }
    return ret;
}

void WebviewController::PutNetworkAvailable(bool available)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        nweb_ptr->PutNetworkAvailable(available);
    }
}

ErrCode WebviewController::HasImagesCallback(napi_env env, napi_ref jsCallback)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        napi_value setResult[RESULT_COUNT] = {0};
        setResult[PARAMZERO] = BusinessError::CreateError(env, NWebError::INIT_ERROR);
        napi_get_null(env, &setResult[PARAMONE]);

        napi_value args[RESULT_COUNT] = {setResult[PARAMZERO], setResult[PARAMONE]};
        napi_value callback = nullptr;
        napi_get_reference_value(env, jsCallback, &callback);
        napi_value callbackResult = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, args, &callbackResult);
        napi_delete_reference(env, jsCallback);
        return NWebError::INIT_ERROR;
    }

    if (jsCallback == nullptr) {
        return NWebError::PARAM_CHECK_ERROR;
    }

    auto callbackImpl = std::make_shared<WebviewHasImageCallback>(env, jsCallback, nullptr);
    nweb_ptr->HasImages(callbackImpl);
    return NWebError::NO_ERROR;
}

ErrCode WebviewController::HasImagesPromise(napi_env env, napi_deferred deferred)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        napi_value jsResult = nullptr;
        jsResult = NWebError::BusinessError::CreateError(env, NWebError::INIT_ERROR);
        napi_reject_deferred(env, deferred, jsResult);
        return NWebError::INIT_ERROR;
    }

    if (deferred == nullptr) {
        return NWebError::PARAM_CHECK_ERROR;
    }

    auto callbackImpl = std::make_shared<WebviewHasImageCallback>(env, nullptr, deferred);
    nweb_ptr->HasImages(callbackImpl);
    return NWebError::NO_ERROR;
}

void WebviewController::RemoveCache(bool includeDiskFiles)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        nweb_ptr->RemoveCache(includeDiskFiles);
    }
}

std::shared_ptr<NWebHistoryList> WebviewController::GetHistoryList()
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return nullptr;
    }
    return nweb_ptr->GetHistoryList();
}

std::shared_ptr<NWebHistoryItem> WebHistoryList::GetItem(int32_t index)
{
    if (!sptrHistoryList_) {
        return nullptr;
    }
    return sptrHistoryList_->GetItem(index);
}

int32_t WebHistoryList::GetListSize()
{
    int32_t listSize = 0;

    if (!sptrHistoryList_) {
        return listSize;
    }
    listSize = sptrHistoryList_->GetListSize();
    return listSize;
}

bool WebviewController::GetFavicon(
    const void **data, size_t &width, size_t &height, ImageColorType &colorType, ImageAlphaType &alphaType) const
{
    bool isGetFavicon = false;
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        isGetFavicon = nweb_ptr->GetFavicon(data, width, height, colorType, alphaType);
    }
    return isGetFavicon;
}

std::vector<uint8_t> WebviewController::SerializeWebState()
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        return nweb_ptr->SerializeWebState();
    }
    std::vector<uint8_t> empty;
    return empty;
}

bool WebviewController::RestoreWebState(const std::vector<uint8_t> &state) const
{
    bool isRestored = false;
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        isRestored = nweb_ptr->RestoreWebState(state);
    }
    return isRestored;
}

void WebviewController::ScrollPageDown(bool bottom)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        nweb_ptr->PageDown(bottom);
    }
    return;
}

void WebviewController::ScrollPageUp(bool top)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        nweb_ptr->PageUp(top);
    }
    return;
}

void WebviewController::ScrollTo(float x, float y)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        nweb_ptr->ScrollTo(x, y);
    }
    return;
}

void WebviewController::ScrollBy(float deltaX, float deltaY)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        nweb_ptr->ScrollBy(deltaX, deltaY);
    }
    return;
}

void WebviewController::SlideScroll(float vx, float vy)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        nweb_ptr->SlideScroll(vx, vy);
    }
    return;
}

void WebviewController::SetScrollable(bool enable)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return;
    }
    std::shared_ptr<OHOS::NWeb::NWebPreference> setting = nweb_ptr->GetPreference();
    if (!setting) {
        return;
    }
    return setting->SetScrollable(enable);
}

bool WebviewController::GetScrollable() const
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return true;
    }
    std::shared_ptr<OHOS::NWeb::NWebPreference> setting = nweb_ptr->GetPreference();
    if (!setting) {
        return true;
    }
    return setting->GetScrollable();
}

void WebviewController::InnerSetHapPath(const std::string &hapPath)
{
    hapPath_ = hapPath;
}
 
void WebviewController::InnerSetFavicon(napi_env env, napi_value favicon)
{
    favicon_.CreateReference(env, favicon);
}

napi_value WebviewController::InnerGetFavicon(napi_env env)
{
    return favicon_.GetRefValue();
}

bool WebviewController::GetCertChainDerData(std::vector<std::string> &certChainDerData) const
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        WVLOG_E("GetCertChainDerData failed, nweb ptr is null");
        return false;
    }

    return nweb_ptr->GetCertChainDerData(certChainDerData, true);
}

ErrCode WebviewController::SetAudioMuted(bool muted)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return NWebError::INIT_ERROR;
    }

    nweb_ptr->SetAudioMuted(muted);
    return NWebError::NO_ERROR;
}

ErrCode WebviewController::PrefetchPage(std::string& url, std::map<std::string, std::string> additionalHttpHeaders)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return NWebError::INIT_ERROR;
    }

    nweb_ptr->PrefetchPage(url, additionalHttpHeaders);
    return NWebError::NO_ERROR;
}

void WebPrintDocument::OnStartLayoutWrite(const std::string& jobId, const PrintAttributesAdapter& oldAttrs,
    const PrintAttributesAdapter& newAttrs, uint32_t fd, std::function<void(std::string, uint32_t)> writeResultCallback)
{
    if (printDocAdapter_) {
        std::shared_ptr<PrintWriteResultCallbackAdapter> callback =
            std::make_shared<WebPrintWriteResultCallbackAdapter>(writeResultCallback);
        printDocAdapter_->OnStartLayoutWrite(jobId, oldAttrs, newAttrs, fd, callback);
    }
}

void WebPrintDocument::OnJobStateChanged(const std::string& jobId, uint32_t state)
{
    if (printDocAdapter_) {
        printDocAdapter_->OnJobStateChanged(jobId, state);
    }
}

void* WebviewController::CreateWebPrintDocumentAdapter(const std::string& jobName)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return nullptr;
    }
    return nweb_ptr->CreateWebPrintDocumentAdapter(jobName);
}

void WebviewController::CloseAllMediaPresentations()
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        nweb_ptr->CloseAllMediaPresentations();
    }
}

void WebviewController::StopAllMedia()
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        nweb_ptr->StopAllMedia();
    }
}

void WebviewController::ResumeAllMedia()
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        nweb_ptr->ResumeAllMedia();
    }
}

void WebviewController::PauseAllMedia()
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        nweb_ptr->PauseAllMedia();
    }
}

int WebviewController::GetMediaPlaybackState()
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return static_cast<int>(MediaPlaybackState::NONE);
    }
    return nweb_ptr->GetMediaPlaybackState();
}

int WebviewController::GetSecurityLevel()
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return static_cast<int>(SecurityLevel::NONE);
    }

    int nwebSecurityLevel = nweb_ptr->GetSecurityLevel();
    SecurityLevel securityLevel;
    switch (nwebSecurityLevel) {
        case static_cast<int>(CoreSecurityLevel::NONE):
            securityLevel = SecurityLevel::NONE;
            break;
        case static_cast<int>(CoreSecurityLevel::SECURE):
            securityLevel = SecurityLevel::SECURE;
            break;
        case static_cast<int>(CoreSecurityLevel::WARNING):
            securityLevel = SecurityLevel::WARNING;
            break;
        case static_cast<int>(CoreSecurityLevel::DANGEROUS):
            securityLevel = SecurityLevel::DANGEROUS;
            break;
        default:
            securityLevel = SecurityLevel::NONE;
            break;
    }

    return static_cast<int>(securityLevel);
}

bool WebviewController::IsIncognitoMode() const
{
    bool incognitoMode = false;
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        incognitoMode = nweb_ptr->IsIncognitoMode();
    }
    return incognitoMode;
}

void WebviewController::SetPrintBackground(bool enable)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        nweb_ptr->SetPrintBackground(enable);
    }
}

bool  WebviewController::GetPrintBackground() const
{
    bool printBackgroundEnabled = false;
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        printBackgroundEnabled = nweb_ptr->GetPrintBackground();
    }

    return printBackgroundEnabled;
}

void WebviewController::EnableIntelligentTrackingPrevention(bool enable)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        nweb_ptr->EnableIntelligentTrackingPrevention(enable);
    }
}

bool WebviewController::IsIntelligentTrackingPreventionEnabled() const
{
    bool enabled = false;
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        enabled = nweb_ptr->IsIntelligentTrackingPreventionEnabled();
    }
    return enabled;
}

void WebPrintWriteResultCallbackAdapter::WriteResultCallback(std::string jobId, uint32_t code)
{
    cb_(jobId, code);
}

bool WebviewController::SetWebSchemeHandler(const char* scheme, WebSchemeHandler* handler) const
{
    if (!handler || !scheme) {
        WVLOG_E("WebviewController::SetWebSchemeHandler handler or scheme is nullptr");
        return false;
    }
    auto schemeHandler_ptr = WebSchemeHandler::GetArkWebSchemeHandler(handler);
    if (!schemeHandler_ptr) {
        WVLOG_E("WebviewController::SetWebSchemeHandler ArkWebSchemeHandler is nullptr");
        return false;
    }
    ArkWeb_SchemeHandler* schemeHandler =
        const_cast<ArkWeb_SchemeHandler*>(schemeHandler_ptr);
    return OH_ArkWeb_SetSchemeHandler(scheme, webTag_.c_str(), schemeHandler);
}

int32_t WebviewController::ClearWebSchemeHandler()
{
    DeleteWebSchemeHandler();
    return OH_ArkWeb_ClearSchemeHandlers(webTag_.c_str());
}

bool WebviewController::SetWebServiveWorkerSchemeHandler(
    const char* scheme, WebSchemeHandler* handler)
{
    auto schemeHandler_ptr = WebSchemeHandler::GetArkWebSchemeHandler(handler);
    if (!schemeHandler_ptr) {
        WVLOG_E("WebviewController::SetWebServiveWorkerSchemeHandler ArkWebSchemeHandler is nullptr");
        return false;
    }
    ArkWeb_SchemeHandler* schemeHandler =
        const_cast<ArkWeb_SchemeHandler*>(schemeHandler_ptr);
    return OH_ArkWebServiceWorker_SetSchemeHandler(scheme, schemeHandler);
}

int32_t WebviewController::ClearWebServiceWorkerSchemeHandler()
{
    DeleteWebServiceWorkerSchemeHandler();
    return OH_ArkWebServiceWorker_ClearSchemeHandlers();
}

ErrCode WebviewController::StartCamera()
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return NWebError::INIT_ERROR;
    }

    nweb_ptr->StartCamera();
    return NWebError::NO_ERROR;
}

ErrCode WebviewController::StopCamera()
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return NWebError::INIT_ERROR;
    }

    nweb_ptr->StopCamera();
    return NWebError::NO_ERROR;
}

ErrCode WebviewController::CloseCamera()
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return NWebError::INIT_ERROR;
    }

    nweb_ptr->CloseCamera();
    return NWebError::NO_ERROR;
}

std::string WebviewController::GetLastJavascriptProxyCallingFrameUrl()
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return "";
    }

    return nweb_ptr->GetLastJavascriptProxyCallingFrameUrl();
}

void WebviewController::OnCreateNativeMediaPlayer(napi_env env, napi_ref callback)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return;
    }

    auto callbackImpl = std::make_shared<NWebCreateNativeMediaPlayerCallbackImpl>(nwebId_, env, callback);
    nweb_ptr->OnCreateNativeMediaPlayer(callbackImpl);
}

bool WebviewController::ParseScriptContent(napi_env env, napi_value value, std::string &script)
{
    napi_valuetype valueType;
    napi_typeof(env, value, &valueType);
    if (valueType == napi_string) {
        std::string str;
        if (!NapiParseUtils::ParseString(env, value, str)) {
            WVLOG_E("PrecompileJavaScript: parse script text to string failed.");
            return false;
        }

        script = str;
        return true;
    }

    std::vector<uint8_t> vec = ParseUint8Array(env, value);
    if (!vec.size()) {
        WVLOG_E("PrecompileJavaScript: parse script text to Uint8Array failed.");
        return false;
    }

    std::string str(vec.begin(), vec.end());
    script = str;
    return true;
}

std::shared_ptr<CacheOptions> WebviewController::ParseCacheOptions(napi_env env, napi_value value) {
    std::map<std::string, std::string> responseHeaders;
    auto defaultCacheOptions = std::make_shared<NWebCacheOptionsImpl>(responseHeaders);

    napi_value responseHeadersValue = nullptr;
    if (napi_get_named_property(env, value, "responseHeaders", &responseHeadersValue) != napi_ok) {
        WVLOG_D("PrecompileJavaScript: cannot get 'responseHeaders' of CacheOptions.");
        return defaultCacheOptions;
    }

    if (!ParseResponseHeaders(env, responseHeadersValue, responseHeaders)) {
        WVLOG_D("PrecompileJavaScript: parse 'responseHeaders' of CacheOptions failed. use default options");
        return defaultCacheOptions;
    }

    return std::make_shared<NWebCacheOptionsImpl>(responseHeaders);
}

void WebviewController::PrecompileJavaScriptPromise(
    napi_env env, napi_deferred deferred,
    const std::string &url, const std::string &script, std::shared_ptr<CacheOptions> cacheOptions)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr || !deferred) {
        return;
    }

    auto callbackImpl = std::make_shared<OHOS::NWeb::NWebPrecompileCallback>();
    callbackImpl->SetCallback([env, deferred](int64_t result) {
        if (!env) {
            return;
        }

        NApiScope scope(env);
        if (!scope.IsVaild()) {
            return;
        }

        napi_value setResult[RESULT_COUNT] = {0};
        napi_create_int64(env, result, &setResult[PARAMZERO]);
        napi_value args[RESULT_COUNT] = {setResult[PARAMZERO]};
        if (result == static_cast<int64_t>(PrecompileError::OK)) {
            napi_resolve_deferred(env, deferred, args[PARAMZERO]);
        } else {
            napi_reject_deferred(env, deferred, args[PARAMZERO]);
        }
    });

    nweb_ptr->PrecompileJavaScript(url, script, cacheOptions, callbackImpl);
}

bool WebviewController::ParseResponseHeaders(napi_env env,
                                             napi_value value,
                                             std::map<std::string, std::string> &responseHeaders) const
{
    bool isArray = false;
    napi_is_array(env, value, &isArray);
    if (!isArray) {
        WVLOG_E("Response headers is not array.");
        return false;
    }

    uint32_t length = INTEGER_ZERO;
    napi_get_array_length(env, value, &length);
    for (uint32_t i = 0; i < length; i++) {
        std::string keyString;
        std::string valueString;
        napi_value header = nullptr;
        napi_value keyObj = nullptr;
        napi_value valueObj = nullptr;
        napi_get_element(env, value, i, &header);

        if (napi_get_named_property(env, header, "headerKey", &keyObj) != napi_ok ||
            !NapiParseUtils::ParseString(env, keyObj, keyString)) {
            continue;
        }

        if (napi_get_named_property(env, header, "headerValue", &valueObj) != napi_ok ||
            !NapiParseUtils::ParseString(env, valueObj, valueString)) {
            continue;
        }

        responseHeaders[keyString] = valueString;
    }

    return true;
}

ParseURLResult WebviewController::ParseURLList(napi_env env, napi_value value, std::vector<std::string>& urlList)
{
    if (!NapiParseUtils::ParseStringArray(env, value, urlList)) {
        return ParseURLResult::FAILED;
    }

    for (auto url : urlList) {
        if (!CheckURL(url)) {
            return ParseURLResult::INVALID_URL;
        }
    }

    return ParseURLResult::OK;
}

bool WebviewController::CheckURL(std::string& url) const
{
    if (url.size() > URL_MAXIMUM) {
        WVLOG_E("The URL exceeds the maximum length of %{public}d. URL: %{private}s", URL_MAXIMUM, url.c_str());
        return false;
    }

    if (!regex_match(url, std::regex("^http(s)?:\\/\\/.+", std::regex_constants::icase))) {
        WVLOG_E("The Parse URL error. URL: %{private}s", url.c_str());
        return false;
    }

    return true;
}

std::vector<uint8_t> WebviewController::ParseUint8Array(napi_env env, napi_value value)
{
    napi_typedarray_type typedArrayType;
    size_t length = 0;
    napi_value buffer = nullptr;
    size_t offset = 0;
    napi_get_typedarray_info(env, value, &typedArrayType, &length, nullptr, &buffer, &offset);
    if (typedArrayType != napi_uint8_array) {
        WVLOG_E("Param is not Unit8Array.");
        return std::vector<uint8_t>();
    }

    uint8_t *data = nullptr;
    size_t total = 0;
    napi_get_arraybuffer_info(env, buffer, reinterpret_cast<void **>(&data), &total);
    length = std::min<size_t>(length, total - offset);
    std::vector<uint8_t> vec(length);
    int retCode = memcpy_s(vec.data(), vec.size(), &data[offset], length);
    if (retCode != 0) {
        WVLOG_E("Parse Uint8Array failed.");
        return std::vector<uint8_t>();
    }

    return vec;
}

void WebviewController::InjectOfflineResource(const std::vector<std::string>& urlList,
                                              const std::vector<uint8_t>& resource,
                                              const std::map<std::string, std::string>& response_headers,
                                              const uint32_t type)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return;
    }

    std::string originUrl = urlList[0];
    if (urlList.size() == 1) {
        nweb_ptr->InjectOfflineResource(originUrl, originUrl, resource, response_headers, type);
        return;
    }

    for (size_t i = 1 ; i < urlList.size() ; i++) {
        nweb_ptr->InjectOfflineResource(urlList[i], originUrl, resource, response_headers, type);
    }
}

void WebviewController::EnableAdsBlock(bool enable)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        nweb_ptr->EnableAdsBlock(enable);
    }
}

bool WebviewController::IsAdsBlockEnabled() const
{
    bool enabled = false;
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        enabled = nweb_ptr->IsAdsBlockEnabled();
    }
    return enabled;
}

bool WebviewController::IsAdsBlockEnabledForCurPage() const
{
    bool enabled = false;
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        enabled = nweb_ptr->IsAdsBlockEnabledForCurPage();
    }
    return enabled;
}

std::string WebviewController::GetSurfaceId()
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return "";
    }
    std::shared_ptr<OHOS::NWeb::NWebPreference> setting = nweb_ptr->GetPreference();
    if (!setting) {
        return "";
    }
    return setting->GetSurfaceId();
}

void WebviewController::UpdateInstanceId(int32_t newId)
{
    if (javaScriptResultCb_) {
        javaScriptResultCb_->UpdateInstanceId(newId);
    }
}

ErrCode WebviewController::SetUrlTrustList(const std::string& urlTrustList, std::string& detailErrMsg)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return NWebError::INIT_ERROR;
    }

    int ret = NWebError::NO_ERROR;
    switch (nweb_ptr->SetUrlTrustListWithErrMsg(urlTrustList, detailErrMsg)) {
        case static_cast<int>(UrlListSetResult::INIT_ERROR):
            ret = NWebError::INIT_ERROR;
            break;
        case static_cast<int>(UrlListSetResult::PARAM_ERROR):
            ret = NWebError::PARAM_CHECK_ERROR;
            break;
        case static_cast<int>(UrlListSetResult::SET_OK):
            ret = NWebError::NO_ERROR;
            break;
        default:
            ret = NWebError::PARAM_CHECK_ERROR;
            break;
    }
    return ret;
}
bool WebviewController::ParseJsLengthResourceToInt(
    napi_env env, napi_value jsLength, PixelUnit &type, int32_t &result) const
{
    napi_value resIdObj = nullptr;
    int32_t resId;

    if ((napi_get_named_property(env, jsLength, "id", &resIdObj) != napi_ok)) {
        return false;
    }

    if (!NapiParseUtils::ParseInt32(env, resIdObj, resId)) {
        return false;
    }

    std::shared_ptr<AbilityRuntime::ApplicationContext> context =
        AbilityRuntime::ApplicationContext::GetApplicationContext();
    if (!context) {
        WVLOG_E("WebPageSnapshot Failed to get application context.");
        return false;
    }
    auto resourceManager = context->GetResourceManager();
    if (!resourceManager) {
        WVLOG_E("WebPageSnapshot Failed to get resource manager.");
        return false;
    }

    napi_value jsResourceType = nullptr;
    napi_valuetype resourceType = napi_null;
    napi_get_named_property(env, jsLength, "type", &jsResourceType);
    napi_typeof(env, jsResourceType, &resourceType);
    if (resourceType == napi_number) {
        int32_t resourceTypeNum;
        NapiParseUtils::ParseInt32(env, jsResourceType, resourceTypeNum);
        std::string resourceString;
        switch (resourceTypeNum) {
            case static_cast<int>(ResourceType::INTEGER):
                if (resourceManager->GetIntegerById(resId, result) == Global::Resource::SUCCESS) {
                    type = PixelUnit::VP;
                    return true;
                }
                break;
            case static_cast<int>(ResourceType::STRING):
                if (resourceManager->GetStringById(resId, resourceString) == Global::Resource::SUCCESS) {
                    return NapiParseUtils::ParseJsLengthStringToInt(resourceString, type, result);
                }
                break;
            default:
                WVLOG_E("WebPageSnapshot resource type not support");
                break;
        }
        return false;
    }
    WVLOG_E("WebPageSnapshot resource type error");
    return false;
}

bool WebviewController::ParseJsLengthToInt(
    napi_env env, napi_value jsLength, PixelUnit &type, int32_t &result) const
{
    napi_valuetype jsType = napi_null;
    napi_typeof(env, jsLength, &jsType);
    if ((jsType != napi_object) && (jsType != napi_string) && (jsType != napi_number)) {
        WVLOG_E("WebPageSnapshot Unable to parse js length object.");
        return false;
    }

    if (jsType == napi_number) {
        NapiParseUtils::ParseInt32(env, jsLength, result);
        type = PixelUnit::VP;
        return true;
    }

    if (jsType == napi_string) {
        std::string nativeString;
        NapiParseUtils::ParseString(env, jsLength, nativeString);
        if (!NapiParseUtils::ParseJsLengthStringToInt(nativeString, type, result)) {
            return false;
        }
        return true;
    }

    if (jsType == napi_object) {
        return ParseJsLengthResourceToInt(env, jsLength, type, result);
    }
    return false;
}

ErrCode WebviewController::WebPageSnapshot(
    const char *id, PixelUnit type, int32_t width, int32_t height, const WebSnapshotCallback callback)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return INIT_ERROR;
    }

    bool init = nweb_ptr->WebPageSnapshot(id, type, width, height, std::move(callback));
    if (!init) {
        return INIT_ERROR;
    }

    return NWebError::NO_ERROR;
}

bool WebviewController::GetHapModuleInfo()
{
    sptr<ISystemAbilityManager> systemAbilityManager =
    SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        WVLOG_E("get SystemAbilityManager failed");
        return false;
    }
    sptr<IRemoteObject> remoteObject =
        systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (remoteObject == nullptr) {
        WVLOG_E("get Bundle Manager failed");
        return false;
    }
    auto bundleMgr = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (bundleMgr == nullptr) {
        WVLOG_E("get Bundle Manager failed");
        return false;
    }
    AppExecFwk::BundleInfo bundleInfo;
    if (bundleMgr->GetBundleInfoForSelf(
        static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE),
        bundleInfo) != 0) {
        WVLOG_E("get bundle info failed");
        return false;
    }
    moduleName_ = bundleInfo.moduleNames;
    return true;
}

void WebviewController::SetPathAllowingUniversalAccess(
    const std::vector<std::string>& pathList, std::string& errorPath)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return;
    }
    if (moduleName_.empty()) {
        WVLOG_I("need to get module name for path");
        if (!GetHapModuleInfo()) {
            WVLOG_E("GetHapModuleInfo failed");
            moduleName_.clear();
            return;
        }
    }
    nweb_ptr->SetPathAllowingUniversalAccess(pathList, moduleName_, errorPath);
}

void WebviewController::ScrollToWithAnime(float x, float y, int32_t duration)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        nweb_ptr->ScrollToWithAnime(x, y, duration);
    }
    return;
}

void WebviewController::ScrollByWithAnime(float deltaX, float deltaY, int32_t duration)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        nweb_ptr->ScrollByWithAnime(deltaX, deltaY, duration);
    }
    return;
}

void WebviewController::SetBackForwardCacheOptions(int32_t size, int32_t timeToLive)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return;
    }

    nweb_ptr->SetBackForwardCacheOptions(size, timeToLive);
}

void WebviewController::GetScrollOffset(float* offset_x, float* offset_y)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        nweb_ptr->GetScrollOffset(offset_x, offset_y);
    }
}

void WebviewController::GetPageOffset(float* offset_x, float* offset_y)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        nweb_ptr->GetPageOffset(offset_x, offset_y);
    }
}

bool WebviewController::ScrollByWithResult(float deltaX, float deltaY) const
{
    bool enabled = false;
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        enabled = nweb_ptr->ScrollByWithResult(deltaX, deltaY);
    }
    return enabled;
}

void WebviewController::SetScrollable(bool enable, int32_t scrollType)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return;
    }
    std::shared_ptr<OHOS::NWeb::NWebPreference> setting = nweb_ptr->GetPreference();
    if (!setting) {
        return;
    }
    return setting->SetScrollable(enable, scrollType);
}

void WebMessageExt::SetType(int type)
{
    type_ = type;
    WebMessageType jsType = static_cast<WebMessageType>(type);
    NWebValue::Type nwebType = NWebValue::Type::NONE;
    NWebRomValue::Type romType = NWebRomValue::Type::NONE;
    switch (jsType) {
        case WebMessageType::STRING: {
            nwebType = NWebValue::Type::STRING;
            romType = NWebRomValue::Type::STRING;
            break;
        }
        case WebMessageType::NUMBER: {
            nwebType = NWebValue::Type::DOUBLE;
            romType = NWebRomValue::Type::DOUBLE;
            break;
        }
        case WebMessageType::BOOLEAN: {
            nwebType = NWebValue::Type::BOOLEAN;
            romType = NWebRomValue::Type::BOOLEAN;
            break;
        }
        case WebMessageType::ARRAYBUFFER: {
            nwebType = NWebValue::Type::BINARY;
            romType = NWebRomValue::Type::BINARY;
            break;
        }
        case WebMessageType::ARRAY: {
            nwebType = NWebValue::Type::STRINGARRAY;
            romType = NWebRomValue::Type::STRINGARRAY;
            break;
        }
        case WebMessageType::ERROR: {
            nwebType = NWebValue::Type::ERROR;
            romType = NWebRomValue::Type::ERROR;
            break;
        }
        default: {
            nwebType = NWebValue::Type::NONE;
            romType = NWebRomValue::Type::NONE;
            break;
        }
    }
    if (data_) {
        data_->SetType(nwebType);
    }
    if (value_) {
        value_->SetType(romType);
    }
}

int WebMessageExt::ConvertNwebType2JsType(NWebValue::Type type)
{
    WebMessageType jsType = WebMessageType::NOTSUPPORT;
    switch (type) {
        case NWebValue::Type::STRING: {
            jsType = WebMessageType::STRING;
            break;
        }
        case NWebValue::Type::DOUBLE:
        case NWebValue::Type::INTEGER: {
            jsType = WebMessageType::NUMBER;
            break;
        }
        case NWebValue::Type::BOOLEAN: {
            jsType = WebMessageType::BOOLEAN;
            break;
        }
        case NWebValue::Type::STRINGARRAY:
        case NWebValue::Type::DOUBLEARRAY:
        case NWebValue::Type::INT64ARRAY:
        case NWebValue::Type::BOOLEANARRAY: {
            jsType = WebMessageType::ARRAY;
            break;
        }
        case NWebValue::Type::BINARY: {
            jsType = WebMessageType::ARRAYBUFFER;
            break;
        }
        case NWebValue::Type::ERROR: {
            jsType = WebMessageType::ERROR;
            break;
        }
        default: {
            jsType = WebMessageType::NOTSUPPORT;
            break;
        }
    }
    return static_cast<int>(jsType);
}

std::shared_ptr<HitTestResult> WebviewController::GetLastHitTest()
{
    std::shared_ptr<HitTestResult> nwebResult;
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        nwebResult = nweb_ptr->GetLastHitTestResult();
        if (nwebResult) {
            nwebResult->SetType(ConverToWebHitTestType(nwebResult->GetType()));
        }
    }
    return nwebResult;
}

void WebviewController::SaveWebSchemeHandler(const char* scheme, WebSchemeHandler* handler)
{
    auto iter = webSchemeHandlerMap_.find(scheme);
    if (iter != webSchemeHandlerMap_.end()) {
        return;
    }
    webSchemeHandlerMap_[scheme] = handler;
}

void WebviewController::SaveWebServiceWorkerSchemeHandler(const char* scheme, WebSchemeHandler* handler)
{
    auto iter = webServiceWorkerSchemeHandlerMap_.find(scheme);
    if (iter != webServiceWorkerSchemeHandlerMap_.end()) {
        return;
    }
    webServiceWorkerSchemeHandlerMap_[scheme] = handler;
}

void WebviewController::DeleteWebSchemeHandler()
{
    for (const auto &iter : webSchemeHandlerMap_) {
        iter.second->DeleteReference(iter.second);
    }
    webSchemeHandlerMap_.clear();
}

void WebviewController::DeleteWebServiceWorkerSchemeHandler()
{
    for (const auto &iter : webServiceWorkerSchemeHandlerMap_) {
        iter.second->DeleteReference(iter.second);
    }
    webServiceWorkerSchemeHandlerMap_.clear();
}

int WebviewController::GetAttachState()
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        return static_cast<int>(attachState_);
    }
    return static_cast<int>(AttachState::NOT_ATTACHED);
}

void WebviewController::RegisterStateChangeCallback(const napi_env& env, const std::string& type, napi_value handler)
{
    napi_ref handlerRef = nullptr;
    napi_create_reference(env, handler, 1, &handlerRef);
    WebRegObj regObj(env, handlerRef);
    auto iter = attachEventRegisterInfo_.find(type);
    if (iter == attachEventRegisterInfo_.end()) {
        attachEventRegisterInfo_[type] = std::vector<WebRegObj> {regObj};
        WVLOG_I("WebviewController::RegisterStateChangeCallback add new type.");
        return;
    }
    bool found = false;
    for (auto& regObjInList : iter->second) {
        if (env == regObjInList.m_regEnv) {
            napi_value handlerTemp = nullptr;
            if (napi_get_reference_value(env, regObjInList.m_regHanderRef, &handlerTemp) != napi_ok) {
                WVLOG_E("WebviewController::RegisterStateChangeCallback Failed to get reference value.");
                napi_delete_reference(env, handlerRef);
                return;
            }
            bool isEqual = false;
            if (napi_strict_equals(env, handlerTemp, handler, &isEqual) != napi_ok) {
                WVLOG_E("WebviewController::RegisterStateChangeCallback Failed to compare handlers.");
                napi_delete_reference(env, handlerRef);
                return;
            }
            if (isEqual) {
                WVLOG_E("WebviewController::RegisterStateChangeCallback handler function is same");
                found = true;
                break;
            }
        }
    }
    if (!found) {
        iter->second.emplace_back(regObj);
    }
}

void WebviewController::DeleteRegisterObj(const napi_env& env, std::vector<WebRegObj>& vecRegObjs, napi_value& handler)
{
    auto iter = vecRegObjs.begin();
    while (iter != vecRegObjs.end()) {
        if (env == iter->m_regEnv && !iter->m_isMarked) {
            napi_value handlerTemp = nullptr;
            napi_status status = napi_get_reference_value(env, iter->m_regHanderRef, &handlerTemp);
            if (status != napi_ok) {
                WVLOG_E("WebviewController::DeleteRegisterObj Failed to get reference value.");
                ++iter;
                continue;
            }
            if (handlerTemp == nullptr) {
                WVLOG_W("WebviewController::DeleteRegisterObj handlerTemp is null");
            }
            if (handler == nullptr) {
                WVLOG_W("WebviewController::DeleteRegisterObj handler is null");
            }
            bool isEqual = false;
            status = napi_strict_equals(env, handlerTemp, handler, &isEqual);
            if (status != napi_ok) {
                WVLOG_E("WebviewController::DeleteRegisterObj Failed to compare handlers.");
                ++iter;
                continue;
            }
            WVLOG_D("WebviewController::DeleteRegisterObj Delete register isEqual = %{public}d", isEqual);
            if (isEqual) {
                iter->m_isMarked = true;
                WVLOG_I("WebviewController::DeleteRegisterObj Delete register object ref.");
                break;
            } else {
                ++iter;
            }
        } else {
            WVLOG_D(
                "WebviewController::DeleteRegisterObj Unregister event, env is not equal %{private}p, : %{private}p",
                env, iter->m_regEnv);
            ++iter;
        }
    }
}

void WebviewController::DeleteAllRegisterObj(const napi_env& env, std::vector<WebRegObj>& vecRegObjs)
{
    auto iter = vecRegObjs.begin();
    for (; iter != vecRegObjs.end();) {
        if (env == iter->m_regEnv && !iter->m_isMarked) {
            iter->m_isMarked = true;
        } else {
            WVLOG_D("WebviewController::DeleteAllRegisterObj Unregister all event, env is not equal %{private}p, : "
                    "%{private}p",
                env, iter->m_regEnv);
            ++iter;
        }
    }
}

void WebviewController::UnregisterStateChangeCallback(const napi_env& env, const std::string& type, napi_value handler)
{
    auto iter = attachEventRegisterInfo_.find(type);
    if (iter == attachEventRegisterInfo_.end()) {
        WVLOG_W("WebviewController::UnregisterStateChangeCallback Unregister type not registered!");
        return;
    }
    if (handler != nullptr) {
        DeleteRegisterObj(env, iter->second, handler);
    } else {
        WVLOG_I("WebviewController::UnregisterStateChangeCallback All callback is unsubscribe for event: %{public}s",
            type.c_str());
        DeleteAllRegisterObj(env, iter->second);
    }
    if (iter->second.empty()) {
        attachEventRegisterInfo_.erase(iter);
    }
}

void WebviewController::WaitForAttached(napi_env env, void* data)
{
    WVLOG_D("WebviewController::WaitForAttached start");
    WaitForAttachParam* param = static_cast<WaitForAttachParam*>(data);
    std::unique_lock<std::mutex> attachLock(param->webviewController->attachMtx_);
    param->webviewController->attachCond_.wait_for(attachLock, std::chrono::milliseconds(param->timeout), [param] {
        return param->webviewController->attachState_ == AttachState::ATTACHED;
    });
    param->state = static_cast<int32_t>(param->webviewController->attachState_);
}

void WebviewController::TriggerWaitforAttachedPromise(napi_env env, napi_status status, void* data)
{
    WaitForAttachParam* param = static_cast<WaitForAttachParam*>(data);
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env, &scope);
    if (scope == nullptr) {
        delete param;
        param = nullptr;
        return;
    }

    WVLOG_D("WebviewController::TriggerWaitforAttachedPromise start");
    if (param->deferred != nullptr) {
        napi_value jsState = nullptr;
        napi_create_int32(env, param->state, &jsState);
        napi_resolve_deferred(env, param->deferred, jsState);
    }
    napi_close_handle_scope(env, scope);
    napi_delete_async_work(env, param->asyncWork);
    delete param;
    param = nullptr;
}

napi_value WebviewController::WaitForAttachedPromise(napi_env env, int32_t timeout, napi_deferred deferred)
{
    napi_value result = nullptr;
    napi_value resourceName = nullptr;
    WaitForAttachParam *param = new (std::nothrow) WaitForAttachParam {
        .asyncWork = nullptr,
        .deferred = deferred,
        .timeout = timeout,
        .webviewController = this,
        .state = static_cast<int32_t>(attachState_),
    };
    if (param == nullptr) {
        return nullptr;
    }

    NAPI_CALL(env, napi_create_string_utf8(env, EVENT_WAIT_FOR_ATTACH.c_str(), NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName, WaitForAttached,
        TriggerWaitforAttachedPromise, static_cast<void *>(param), &param->asyncWork));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, param->asyncWork, napi_qos_user_initiated));
    napi_get_undefined(env, &result);
    return result;
}

int32_t WebviewController::GetBlanklessInfoWithKey(const std::string& key, double* similarity, int32_t* loadingTime)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        return nweb_ptr->GetBlanklessInfoWithKey(key, similarity, loadingTime);
    }
    return -1;
}

int32_t WebviewController::SetBlanklessLoadingWithKey(const std::string& key, bool isStart)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (nweb_ptr) {
        return nweb_ptr->SetBlanklessLoadingWithKey(key, isStart);
    }
    return -1;
}

ErrCode WebviewController::AvoidVisibleViewportBottom(int32_t avoidHeight)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return INIT_ERROR;
    }
    nweb_ptr->AvoidVisibleViewportBottom(avoidHeight);
    return NWebError::NO_ERROR;
}

ErrCode WebviewController::SetErrorPageEnabled(bool enable)
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return INIT_ERROR;
    }
    nweb_ptr->SetErrorPageEnabled(enable);
    return NWebError::NO_ERROR;
}

bool WebviewController::GetErrorPageEnabled()
{
    auto nweb_ptr = NWebHelper::Instance().GetNWeb(nwebId_);
    if (!nweb_ptr) {
        return false;
    }
    return nweb_ptr->GetErrorPageEnabled();
}
} // namespace NWeb
} // namespace OHOS
