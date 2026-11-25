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

#include "arkweb_interface.h"

#include <atomic>

#include "arkweb_type.h"
#include "nweb_helper.h"
#include "nweb_log.h"
#include "arkweb_error_code.h"

namespace {
#define ARKWEB_NATIVE_FOR_EACH_COMPONENT_API_FN(DO)           \
    DO(onControllerAttached, OH_ArkWeb_OnControllerAttached); \
    DO(onPageBegin, OH_ArkWeb_OnPageBegin);                   \
    DO(onPageEnd, OH_ArkWeb_OnPageEnd);                       \
    DO(onDestroy, OH_ArkWeb_OnDestroy)

#define ARKWEB_NATIVE_FOR_EACH_COMPONENT_GLOBAL_API_FN(DO)    \
    DO(onScroll, OH_ArkWeb_OnScroll)

#define ARKWEB_NATIVE_FOR_EACH_CONTROLLER_API_FN(DO)                          \
    DO(runJavaScript, OH_ArkWeb_RunJavaScript);                               \
    DO(registerJavaScriptProxy, OH_ArkWeb_RegisterJavaScriptProxy);           \
    DO(deleteJavaScriptRegister, OH_ArkWeb_DeleteJavaScriptProxy);            \
    DO(refresh, OH_ArkWeb_Refresh);                                           \
    DO(registerAsyncJavaScriptProxy, OH_ArkWeb_RegisterAsyncJavaScriptProxy); \
    DO(createWebMessagePorts, OH_ArkWeb_CreateWebMessagePorts);               \
    DO(destroyWebMessagePorts, OH_ArkWeb_DestroyWebMessagePorts);             \
    DO(postWebMessage, OH_ArkWeb_PostWebMessage);                             \
    DO(getLastJavascriptProxyCallingFrameUrl, OH_ArkWeb_GetLastJavascriptProxyCallingFrameUrl)

#define ARKWEB_NATIVE_FOR_EACH_CONTROLLER_API_FN_2(DO)                        \
    DO(registerJavaScriptProxyEx,                                             \
        OH_ArkWeb_RegisterJavaScriptProxyEx);                                 \
    DO(registerAsyncJavaScriptProxyEx,                                        \
        OH_ArkWeb_RegisterAsyncJavaScriptProxyEx)

#define ARKWEB_NATIVE_FOR_EACH_WEBMESSAGEPORT_API_FN(DO) \
    DO(postMessage, OH_WebMessage_PostMessage);          \
    DO(close, OH_WebMessage_Close);                      \
    DO(setMessageEventHandler, OH_WebMessage_SetMessageEventHandler)

#define ARKWEB_NATIVE_FOR_EACH_WEBMESSAGE_API_FN(DO)        \
    DO(createWebMessage, OH_WebMessage_CreateWebMessage);   \
    DO(destroyWebMessage, OH_WebMessage_DestroyWebMessage); \
    DO(setType, OH_WebMessage_SetType);                     \
    DO(getType, OH_WebMessage_GetType);                     \
    DO(setData, OH_WebMessage_SetData);                     \
    DO(getData, OH_WebMessage_GetData)

#define ARKWEB_NATIVE_FOR_EACH_WEBCOOKIEMANAGER_API_FN(DO)                \
    DO(fetchCookieSync, OH_CookieManager_FetchCookieSync);                \
    DO(configCookieSync, OH_CookieManager_ConfigCookieSync);              \
    DO(existCookies, OH_CookieManager_ExistCookies);                      \
    DO(clearAllCookiesSync, OH_CookieManager_ClearAllCookiesSync);        \
    DO(clearSessionCookiesSync, OH_CookieManager_ClearSessionCookiesSync)

#define ARKWEB_NATIVE_FOR_EACH_JAVASCRIPTVALUE_API_FN(DO)             \
    DO(createJavaScriptValue, OH_JavaScript_CreateJavaScriptValue)

std::atomic<ArkWeb_ComponentAPI*> g_ComponentImpl{nullptr};
std::atomic<ArkWeb_ControllerAPI*> g_ControllerImpl{nullptr};
std::atomic<ArkWeb_WebMessagePortAPI*> g_WebMessagePortImpl{nullptr};
std::atomic<ArkWeb_WebMessageAPI*> g_WebMessageImpl{nullptr};
std::atomic<ArkWeb_CookieManagerAPI*> g_CookieManagerImpl{nullptr};
std::atomic<ArkWeb_JavaScriptValueAPI*> g_JavaScriptValueImpl{nullptr};

typedef struct {
    /** The ArkWeb_ComponentGlobalAPI struct size. */
    size_t size;
    /** Register the onScroll callback. */
    bool (*onScroll)(const char* webTag, ArkWeb_OnScrollCallback callback, void* userData);
} ArkWeb_ComponentGlobalAPI;

std::atomic<ArkWeb_ComponentGlobalAPI*> g_ComponentGlobalImpl{nullptr};

} // namespace

template<typename Fn>
static void LoadFunction(const char* functionName, Fn* fnOut)
{
    void* fn = OHOS::NWeb::NWebHelper::Instance().LoadFuncSymbol(functionName);
    if (!fn) {
        WVLOG_E("%{public}s not found.", functionName);
        return;
    }
    *fnOut = reinterpret_cast<Fn>(fn);
}

static bool LoadComponentAPI()
{
    if (g_ComponentImpl.load(std::memory_order_acquire)) {
        WVLOG_D("NativeArkWeb component api already loaded");
        return true;
    }
    ArkWeb_ComponentAPI* componentApi = new (std::nothrow) ArkWeb_ComponentAPI();
    if (!componentApi) {
        WVLOG_E("NativeArkWeb component api is nullptr");
        return false;
    }
    componentApi->size = sizeof(ArkWeb_ComponentAPI);

    if (!OHOS::NWeb::NWebHelper::Instance().LoadWebEngine(true, false)) {
        WVLOG_E("NativeArkWeb webEngineHandle is nullptr");
        delete componentApi;
        return false;
    }
#define ARKWEB_NATIVE_LOAD_FN_PTR(fn, ndkFn) LoadFunction(#ndkFn, &(componentApi->fn))
    ARKWEB_NATIVE_FOR_EACH_COMPONENT_API_FN(ARKWEB_NATIVE_LOAD_FN_PTR);
#undef ARKWEB_NATIVE_LOAD_FN_PTR

    ArkWeb_ComponentAPI* expected = nullptr;
    if (!g_ComponentImpl.compare_exchange_strong(
        expected, componentApi, std::memory_order_acq_rel, std::memory_order_acquire)) {
        delete componentApi;
    }
    return true;
}

static bool LoadComponentGlobalAPI()
{
    if (g_ComponentGlobalImpl.load(std::memory_order_acquire)) {
        WVLOG_D("NativeArkWeb component api already loaded");
        return true;
    }

    ArkWeb_ComponentGlobalAPI* componentGlobalApi = new (std::nothrow) ArkWeb_ComponentGlobalAPI();
    if (!componentGlobalApi) {
        WVLOG_E("NativeArkWeb component global api is nullptr");
        return false;
    }
    componentGlobalApi->size = sizeof(ArkWeb_ComponentGlobalAPI);

    if (!OHOS::NWeb::NWebHelper::Instance().LoadWebEngine(true, false)) {
        WVLOG_E("NativeArkWeb webEngineHandle is nullptr");
        delete componentGlobalApi;
        return false;
    }

#define ARKWEB_NATIVE_LOAD_FN_PTR(fn, ndkFn) LoadFunction(#ndkFn, &(componentGlobalApi->fn))
    ARKWEB_NATIVE_FOR_EACH_COMPONENT_GLOBAL_API_FN(ARKWEB_NATIVE_LOAD_FN_PTR);
#undef ARKWEB_NATIVE_LOAD_FN_PTR

    ArkWeb_ComponentGlobalAPI* expected = nullptr;
    if (!g_ComponentGlobalImpl.compare_exchange_strong(
        expected, componentGlobalApi, std::memory_order_acq_rel, std::memory_order_acquire)) {
        delete componentGlobalApi;
    }
    return true;
}

static bool LoadControllerAPI()
{
    if (g_ControllerImpl.load(std::memory_order_acquire)) {
        WVLOG_D("NativeArkWeb controller api already loaded");
        return true;
    }
    ArkWeb_ControllerAPI* controllerApi = new (std::nothrow) ArkWeb_ControllerAPI();
    if (!controllerApi) {
        WVLOG_E("NativeArkWeb controller api is nullptr");
        return false;
    }
    controllerApi->size = sizeof(ArkWeb_ControllerAPI);

    if (!OHOS::NWeb::NWebHelper::Instance().LoadWebEngine(true, false)) {
        WVLOG_E("NativeArkWeb webEngineHandle is nullptr");
        delete controllerApi;
        return false;
    }
#define ARKWEB_NATIVE_LOAD_FN_PTR(fn, ndkFn) LoadFunction(#ndkFn, &(controllerApi->fn))
    ARKWEB_NATIVE_FOR_EACH_CONTROLLER_API_FN(ARKWEB_NATIVE_LOAD_FN_PTR);
#undef ARKWEB_NATIVE_LOAD_FN_PTR

#define ARKWEB_NATIVE_LOAD_FN_PTR(fn, ndkFn) LoadFunction(#ndkFn, &(controllerApi->fn))
    ARKWEB_NATIVE_FOR_EACH_CONTROLLER_API_FN_2(ARKWEB_NATIVE_LOAD_FN_PTR);
#undef ARKWEB_NATIVE_LOAD_FN_PTR

    ArkWeb_ControllerAPI* expected = nullptr;
    if (!g_ControllerImpl.compare_exchange_strong(
        expected, controllerApi, std::memory_order_acq_rel, std::memory_order_acquire)) {
        delete controllerApi;
    }
    return true;
}

static bool LoadWebMessagePortAPI()
{
    if (g_WebMessagePortImpl.load(std::memory_order_acquire)) {
        WVLOG_I("NativeArkWeb web message port api already loaded");
        return true;
    }
    ArkWeb_WebMessagePortAPI* webMessagePortApi = new (std::nothrow) ArkWeb_WebMessagePortAPI();
    if (!webMessagePortApi) {
        WVLOG_E("NativeArkWeb web message port api is nullptr");
        return false;
    }
    webMessagePortApi->size = sizeof(ArkWeb_WebMessagePortAPI);

    if (!OHOS::NWeb::NWebHelper::Instance().LoadWebEngine(true, false)) {
        WVLOG_E("NativeArkWeb webEngineHandle is nullptr");
        delete webMessagePortApi;
        return false;
    }
#define ARKWEB_NATIVE_LOAD_FN_PTR(fn, ndkFn) LoadFunction(#ndkFn, &(webMessagePortApi->fn))
    ARKWEB_NATIVE_FOR_EACH_WEBMESSAGEPORT_API_FN(ARKWEB_NATIVE_LOAD_FN_PTR);
#undef ARKWEB_NATIVE_LOAD_FN_PTR

    ArkWeb_WebMessagePortAPI* expected = nullptr;
    if (!g_WebMessagePortImpl.compare_exchange_strong(
        expected, webMessagePortApi, std::memory_order_acq_rel, std::memory_order_acquire)) {
        delete webMessagePortApi;
    }
    return true;
}

static bool LoadWebMessageAPI()
{
    if (g_WebMessageImpl.load(std::memory_order_acquire)) {
        WVLOG_I("NativeArkWeb web message api already loaded");
        return true;
    }
    ArkWeb_WebMessageAPI* webMessageApi = new (std::nothrow) ArkWeb_WebMessageAPI();
    if (!webMessageApi) {
        WVLOG_E("NativeArkWeb web message api is nullptr");
        return false;
    }
    webMessageApi->size = sizeof(ArkWeb_WebMessageAPI);

    if (!OHOS::NWeb::NWebHelper::Instance().LoadWebEngine(true, false)) {
        WVLOG_E("NativeArkWeb webEngineHandle is nullptr");
        delete webMessageApi;
        return false;
    }
#define ARKWEB_NATIVE_LOAD_FN_PTR(fn, ndkFn) LoadFunction(#ndkFn, &(webMessageApi->fn))
    ARKWEB_NATIVE_FOR_EACH_WEBMESSAGE_API_FN(ARKWEB_NATIVE_LOAD_FN_PTR);
#undef ARKWEB_NATIVE_LOAD_FN_PTR

    ArkWeb_WebMessageAPI* expected = nullptr;
    if (!g_WebMessageImpl.compare_exchange_strong(
        expected, webMessageApi, std::memory_order_acq_rel, std::memory_order_acquire)) {
        delete webMessageApi;
    }
    return true;
}

static bool LoadCookieManagerAPI()
{
    if (g_CookieManagerImpl.load(std::memory_order_acquire)) {
        WVLOG_I("NativeArkWeb cookie manager api already loaded");
        return true;
    }

    ArkWeb_CookieManagerAPI* cookieManagerApi = new (std::nothrow) ArkWeb_CookieManagerAPI();
    if (!cookieManagerApi) {
        WVLOG_E("NativeArkWeb cookie manager api is nullptr");
        return false;
    }
    cookieManagerApi->size = sizeof(ArkWeb_CookieManagerAPI);

    bool lazy = OHOS::NWeb::NWebHelper::Instance().IsLazyInitializeWebEngine();
    if (!OHOS::NWeb::NWebHelper::Instance().LoadWebEngine(true, !lazy)) {
        WVLOG_E("NativeArkWeb webEngineHandle is nullptr");
        delete cookieManagerApi;
        return false;
    }
#define ARKWEB_NATIVE_LOAD_FN_PTR(fn, ndkFn) LoadFunction(#ndkFn, &(cookieManagerApi->fn))
    ARKWEB_NATIVE_FOR_EACH_WEBCOOKIEMANAGER_API_FN(ARKWEB_NATIVE_LOAD_FN_PTR);
#undef ARKWEB_NATIVE_LOAD_FN_PTR

    ArkWeb_CookieManagerAPI* expected = nullptr;
    if (!g_CookieManagerImpl.compare_exchange_strong(
        expected, cookieManagerApi, std::memory_order_acq_rel, std::memory_order_acquire)) {
        delete cookieManagerApi;
    }
    return true;
}

static bool LoadJavaScriptValueAPI()
{
    if (g_JavaScriptValueImpl.load(std::memory_order_acquire)) {
        WVLOG_I("NativeArkWeb javaScript value api already loaded");
        return true;
    }

    ArkWeb_JavaScriptValueAPI* javaScriptValueApi = new (std::nothrow) ArkWeb_JavaScriptValueAPI();
    if (!javaScriptValueApi) {
        WVLOG_E("NativeArkWeb javaScript value api is nullptr");
        return false;
    }
    javaScriptValueApi->size = sizeof(ArkWeb_JavaScriptValueAPI);

    if (!OHOS::NWeb::NWebHelper::Instance().LoadWebEngine(true, false)) {
        WVLOG_E("NativeArkWeb webEngineHandle is nullptr");
        delete javaScriptValueApi;
        return false;
    }
#define ARKWEB_NATIVE_LOAD_FN_PTR(fn, ndkFn) LoadFunction(#ndkFn, &(javaScriptValueApi->fn))
    ARKWEB_NATIVE_FOR_EACH_JAVASCRIPTVALUE_API_FN(ARKWEB_NATIVE_LOAD_FN_PTR);
#undef ARKWEB_NATIVE_LOAD_FN_PTR

    ArkWeb_JavaScriptValueAPI* expected = nullptr;
    if (!g_JavaScriptValueImpl.compare_exchange_strong(
        expected, javaScriptValueApi, std::memory_order_acq_rel, std::memory_order_acquire)) {
        delete javaScriptValueApi;
    }
    return true;
}

ArkWeb_AnyNativeAPI* OH_ArkWeb_GetNativeAPI(ArkWeb_NativeAPIVariantKind type)
{
    switch (type) {
        case ARKWEB_NATIVE_COMPONENT: {
            if (!LoadComponentAPI()) {
                return nullptr;
            }
            return reinterpret_cast<ArkWeb_AnyNativeAPI*>(g_ComponentImpl.load(std::memory_order_acquire));
        }
        case ARKWEB_NATIVE_CONTROLLER: {
            if (!LoadControllerAPI()) {
                return nullptr;
            }
            return reinterpret_cast<ArkWeb_AnyNativeAPI*>(g_ControllerImpl.load(std::memory_order_acquire));
        }
        case ARKWEB_NATIVE_WEB_MESSAGE_PORT: {
            if (!LoadWebMessagePortAPI()) {
                return nullptr;
            }
            return reinterpret_cast<ArkWeb_AnyNativeAPI*>(g_WebMessagePortImpl.load(std::memory_order_acquire));
        }
        case ARKWEB_NATIVE_WEB_MESSAGE: {
            if (!LoadWebMessageAPI()) {
                return nullptr;
            }
            return reinterpret_cast<ArkWeb_AnyNativeAPI*>(g_WebMessageImpl.load(std::memory_order_acquire));
        }
        case ARKWEB_NATIVE_COOKIE_MANAGER: {
            if (!LoadCookieManagerAPI()) {
                return nullptr;
            }
            return reinterpret_cast<ArkWeb_AnyNativeAPI*>(g_CookieManagerImpl.load(std::memory_order_acquire));
        }
        case ARKWEB_NATIVE_JAVASCRIPT_VALUE: {
            if (!LoadJavaScriptValueAPI()) {
                return nullptr;
            }
            return reinterpret_cast<ArkWeb_AnyNativeAPI*>(g_JavaScriptValueImpl.load(std::memory_order_acquire));
        }
        default: {
            WVLOG_E("fail to get %{public}d arkweb api family", type);
            return nullptr;
        }
    }
}

bool OH_ArkWeb_RegisterScrollCallback(
    const char* webTag, ArkWeb_OnScrollCallback callback, void* userData)
{
    if (!LoadComponentGlobalAPI()) {
        return false;
    }
    ArkWeb_ComponentGlobalAPI* componentGlobalApi = g_ComponentGlobalImpl.load(std::memory_order_acquire);
    if (!componentGlobalApi || !componentGlobalApi->onScroll) {
        return false;
    }
    return componentGlobalApi->onScroll(webTag, callback, userData);
}

[[maybe_unused]] void OH_ArkWeb_DestroyGlobalPointersForTest(void)
{
    ArkWeb_ComponentAPI* componentApi = g_ComponentImpl.exchange(nullptr);
    if (componentApi != nullptr) {
        delete componentApi;
    }

    ArkWeb_ControllerAPI* controllerApi = g_ControllerImpl.exchange(nullptr);
    if (controllerApi != nullptr) {
        delete controllerApi;
    }

    ArkWeb_WebMessagePortAPI* webMessagePortApi = g_WebMessagePortImpl.exchange(nullptr);
    if (webMessagePortApi != nullptr) {
        delete webMessagePortApi;
    }

    ArkWeb_WebMessageAPI* webMessageApi = g_WebMessageImpl.exchange(nullptr);
    if (webMessageApi != nullptr) {
        delete webMessageApi;
    }

    ArkWeb_CookieManagerAPI* cookieManagerApi = g_CookieManagerImpl.exchange(nullptr);
    if (cookieManagerApi != nullptr) {
        delete cookieManagerApi;
    }

    ArkWeb_JavaScriptValueAPI* javaScriptValueApi = g_JavaScriptValueImpl.exchange(nullptr);
    if (javaScriptValueApi != nullptr) {
        delete javaScriptValueApi;
    }

    ArkWeb_ComponentGlobalAPI* componentGlobalApi = g_ComponentGlobalImpl.exchange(nullptr);
    if (componentGlobalApi != nullptr) {
        delete componentGlobalApi;
    }
}
