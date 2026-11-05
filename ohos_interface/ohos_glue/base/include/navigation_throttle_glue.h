/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_GLUE_NAVIGATION_THROTTLE_GLUE_H_
#define OHOS_GLUE_NAVIGATION_THROTTLE_GLUE_H_

#include <cstdint>
#include <functional>
#include <mutex>
#include <unordered_map>

namespace arkweb {

// Actions mirroring OHOS::NWeb::NWebThrottleAction (spec: PROCEED=0/CANCEL=1/
// DEFER=2). Kept as a glue-local enum so this layer does not depend on the
// web_webview interface headers.
enum class ThrottleAction : int32_t {
    PROCEED = 0,
    CANCEL = 1,
    DEFER = 2,
};

// Stages mirroring OHOS::NWeb::NWebThrottleStage.
enum class ThrottleStage : int32_t {
    WILL_START_REQUEST = 0,
    WILL_REDIRECT_REQUEST = 1,
    WILL_PROCESS_RESPONSE = 2,
    WILL_FAIL_REQUEST = 3,
};

// Navigation information crossing the glue boundary. String fields are
// owned by the caller and valid for the duration of the dispatch call only.
struct ThrottleInfo {
    const char* url = nullptr;
    bool isMainFrame = false;
    bool hasUserGesture = false;
    bool isRendererInitiated = false;
    bool isRedirect = false;
    int32_t pageTransition = 0;
    const char* requestMethod = nullptr;
    int32_t statusCode = 0;
    const char* mimeType = nullptr;
    const char* contentDisposition = nullptr;
    int32_t errorCode = 0;
    const char* errorDescription = nullptr;
};

// Per-defer resolution channel back to the Chromium-side throttle. Invoked on
// an arbitrary thread; implementors must post the resolution to the UI thread
// (design D2).
using ThrottleDeferSink = std::function<void(bool proceed)>;

// Dispatcher installed per WebContents by the NWeb delegate. Converts glue
// types to NWeb types and forwards to the registered application handler
// synchronously on the calling (UI) thread.
using ThrottleDispatcher = std::function<ThrottleAction(
    ThrottleStage stage, const ThrottleInfo& info,
    ThrottleDeferSink deferSink, uint64_t& deferId)>;

// Result of a DispatchEvent call. dispatched is false when no dispatcher is
// registered and the caller must proceed with the navigation; otherwise
// action and deferId carry the dispatcher's decision.
struct ThrottleResult {
    bool dispatched = false;
    ThrottleAction action = ThrottleAction::PROCEED;
    uint64_t deferId = 0;
};

// Process-wide router between Chromium-side navigation throttles and per-Web
// dispatchers (design D5: the registry lives in the NWeb delegate; this router
// only maps a WebContents to its dispatcher).
//
// This file is synced into the Chromium source tree (ohos_glue/) where it is
// compiled without Chromium headers, so the WebContents identity is carried as
// an opaque pointer key: Chromium-side callers pass the WebContents* value,
// which uniquely identifies the WebContents for its lifetime. Ownership is not
// transferred; the NWeb delegate must call UnregisterDispatcher on handler
// clear or Web destruction.
class NavigationThrottleGlue {
public:
    static NavigationThrottleGlue* GetInstance();

    NavigationThrottleGlue(const NavigationThrottleGlue&) = delete;
    NavigationThrottleGlue& operator=(const NavigationThrottleGlue&) = delete;

    // Called by the NWeb delegate when a throttle handler is registered.
    // webContentsKey is the WebContents* value (opaque here).
    void RegisterDispatcher(void* webContentsKey, ThrottleDispatcher dispatcher);

    // Called by the NWeb delegate on handler clear or Web destruction.
    void UnregisterDispatcher(void* webContentsKey);

    // Hot-path check for the CreateThrottlesForNavigation short-circuit
    // (spec AC-6.1: no dispatcher means zero-overhead opt-out).
    bool HasDispatcher(void* webContentsKey);

    // Dispatches a throttle event. See ThrottleResult for the return value.
    ThrottleResult DispatchEvent(void* webContentsKey,
                                 ThrottleStage stage,
                                 const ThrottleInfo& info,
                                 ThrottleDeferSink deferSink);

private:
    NavigationThrottleGlue() = default;
    ~NavigationThrottleGlue() = default;

    // Returns the dispatcher registered for webContentsKey, or a null
    // function when none is registered.
    ThrottleDispatcher FindDispatcher(void* webContentsKey);

    std::mutex mutex_;
    std::unordered_map<void*, ThrottleDispatcher> dispatchers_;
};

} // namespace arkweb

#endif // OHOS_GLUE_NAVIGATION_THROTTLE_GLUE_H_
