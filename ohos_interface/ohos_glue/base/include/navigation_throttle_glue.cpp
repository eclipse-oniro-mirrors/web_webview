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

#include "navigation_throttle_glue.h"

namespace arkweb {

namespace {

NavigationThrottleGlue* g_glueInstance = nullptr;

} // namespace

// static
NavigationThrottleGlue* NavigationThrottleGlue::GetInstance()
{
    if (g_glueInstance == nullptr) {
        static NavigationThrottleGlue instance;
        g_glueInstance = &instance;
    }
    return g_glueInstance;
}

void NavigationThrottleGlue::RegisterDispatcher(
    void* webContentsKey, ThrottleDispatcher dispatcher)
{
    if (webContentsKey == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    dispatchers_[webContentsKey] = std::move(dispatcher);
}

void NavigationThrottleGlue::UnregisterDispatcher(void* webContentsKey)
{
    if (webContentsKey == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    dispatchers_.erase(webContentsKey);
}

bool NavigationThrottleGlue::HasDispatcher(void* webContentsKey)
{
    if (webContentsKey == nullptr) {
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    return dispatchers_.find(webContentsKey) != dispatchers_.end();
}

ThrottleDispatcher NavigationThrottleGlue::FindDispatcher(void* webContentsKey)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = dispatchers_.find(webContentsKey);
    if (it == dispatchers_.end()) {
        return nullptr;
    }
    return it->second;
}

ThrottleResult NavigationThrottleGlue::DispatchEvent(void* webContentsKey,
                                                     ThrottleStage stage,
                                                     const ThrottleInfo& info,
                                                     ThrottleDeferSink deferSink)
{
    ThrottleResult result;
    if (webContentsKey == nullptr) {
        return result;
    }
    ThrottleDispatcher dispatcher = FindDispatcher(webContentsKey);
    if (dispatcher == nullptr) {
        return result;
    }
    // Dispatched without holding the lock: the dispatcher calls back into the
    // application synchronously on the UI thread (spec BR-6).
    result.action = dispatcher(stage, info, std::move(deferSink), result.deferId);
    result.dispatched = true;
    return result;
}

} // namespace arkweb
