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

#include "native_interface_arkweb.h"
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

#include "native_arkweb_utils.h"
#include "native_javascript_execute_callback.h"
#include "nweb.h"
#include "nweb_log.h"

std::mutex g_mtx_map; // the mutex to protect the shared resource
std::unordered_map<std::string, NativeArkWeb_OnValidCallback> g_validMap;
std::unordered_map<std::string, NativeArkWeb_OnDestroyCallback> g_destroyMap;

using namespace OHOS;
void OH_NativeArkWeb_RunJavaScript(const char* webTag, const char* jsCode, NativeArkWeb_OnJavaScriptCallback callback)
{
    std::weak_ptr<OHOS::NWeb::NWeb> nwebWeak = OH_NativeArkWeb_GetWebInstanceByWebTag(webTag);
    if (auto nweb = nwebWeak.lock()) {
        auto callbackImpl = std::make_shared<OHOS::NWeb::NativeJavaScriptExecuteCallback>(callback);
        WVLOG_I("native RunJavaScript webTag: %{public}s", webTag);
        nweb->ExecuteJavaScript(jsCode, callbackImpl, false);
    } else {
        WVLOG_E("native RunJavaScript get nweb null: %{public}s", webTag);
    }
}

void OH_NativeArkWeb_RegisterJavaScriptProxy(
    const char* webTag, const char* objName, const char** methodName, NativeArkWeb_OnJavaScriptProxyCallback* callback, int32_t size, bool isNeedRefresh)
{
    WVLOG_I("native OH_NativeArkWeb_RegisterJavaScriptProxy webTag:%{public}s", webTag);
    std::vector<std::function<char*(const char**, int32_t size)>> callbackList;
    for (int i = 0; i < size; i++) {
        callbackList.emplace_back(callback[i]);
    }        

    std::weak_ptr<OHOS::NWeb::NWeb> nwebWeak = OH_NativeArkWeb_GetWebInstanceByWebTag(webTag);
    if (auto nweb = nwebWeak.lock()) {
        nweb->RegisterNativeArkJSFunction(objName, methodName, callbackList, size);
        if (isNeedRefresh) {
            nweb->Reload();
        }
    } else {
        WVLOG_E("native RegisterJavaScriptProxy get nweb null: %{public}s", webTag);
    }
}

void OH_NativeArkWeb_UnregisterJavaScriptProxy(const char* webTag, const char* objName)
{
    WVLOG_I("native OH_NativeArkWeb_RegisterJavaScriptProxy: %{public}s", webTag);
    std::weak_ptr<OHOS::NWeb::NWeb> nwebWeak = OH_NativeArkWeb_GetWebInstanceByWebTag(webTag);
    if (auto nweb = nwebWeak.lock()) {
        nweb->UnRegisterNativeArkJSFunction(objName);
    } else {
        WVLOG_E("native RegisterJavaScriptProxy get nweb null: %{public}s", webTag);
    }
}

void OH_NativeArkWeb_SetDestroyCallback(const char* webTag, NativeArkWeb_OnDestroyCallback callback)
{
    WVLOG_I("native RegisterDestroyCallback, webTag: %{public}s", webTag);
    std::lock_guard<std::mutex> guard(g_mtx_map);
    g_destroyMap[webTag] = callback;
    std::weak_ptr<OHOS::NWeb::NWeb> nwebWeak = OH_NativeArkWeb_GetWebInstanceByWebTag(webTag);
    if (auto nweb = nwebWeak.lock()) {
        WVLOG_I("native RegisterNativeDestroyCallback call nweb");
        nweb->RegisterNativeDestroyCallback(webTag, callback);
    } else {
        WVLOG_E("native RegisterDestroyCallback get nweb null: %{public}s", webTag);
    }
}

NativeArkWeb_OnDestroyCallback OH_NativeArkWeb_GetDestroyCallback(const char* webTag)
{
    WVLOG_I("native OH_Web_GetDestroyCallback, webTag: %{public}s", webTag);
    std::lock_guard<std::mutex> guard(g_mtx_map);
    std::unordered_map<std::string, NativeArkWeb_OnDestroyCallback>::iterator iter;
    if ((iter = g_destroyMap.find(webTag)) != g_destroyMap.end()) {
        return iter->second;
    }
    return nullptr;
}

void OH_NativeArkWeb_SetJavaScriptProxyValidCallback(const char* webTag, NativeArkWeb_OnValidCallback callback)
{
    WVLOG_I("native RegisterValidCallback, webTag: %{public}s", webTag);
    std::lock_guard<std::mutex> guard(g_mtx_map);
    g_validMap[webTag] = callback;
    std::weak_ptr<OHOS::NWeb::NWeb> nwebWeak = OH_NativeArkWeb_GetWebInstanceByWebTag(webTag);
    if (auto nweb = nwebWeak.lock()) {
        WVLOG_I("native OH_NativeArkWeb_SetJavaScriptProxyValidCallback call nweb");
        nweb->RegisterNativeValideCallback(webTag, callback);
    } else {
        WVLOG_E("native RegisterDestroyCallback get nweb null: %{public}s", webTag);
    }
}

NativeArkWeb_OnValidCallback OH_NativeArkWeb_GetJavaScriptProxyValidCallback(const char* webTag)
{
    WVLOG_I("native OH_Web_GetValidCallback, webTag: %{public}s", webTag);
    std::lock_guard<std::mutex> guard(g_mtx_map);
    std::unordered_map<std::string, NativeArkWeb_OnValidCallback>::iterator iter;
    if ((iter = g_validMap.find(webTag)) != g_validMap.end()) {
        return iter->second;
    }
    return nullptr;
}