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
#ifndef WEB_WEBVIEW_ARKWEB_UTILS_WEB_SURFACE_REGISTRY_H
#define WEB_WEBVIEW_ARKWEB_UTILS_WEB_SURFACE_REGISTRY_H

#include <cstdint>
#include <memory>
#include <shared_mutex>
#include <unordered_map>

#ifndef ARKWEB_EXPORT
#define ARKWEB_EXPORT __attribute__((visibility("default")))
#endif

namespace OHOS::Rosen {
class RSNode;
}

namespace OHOS::NWeb {

class ARKWEB_EXPORT WebDelegateSurfaceRegistry {
public:
    static WebDelegateSurfaceRegistry& Instance();
    ~WebDelegateSurfaceRegistry() = default;

    void SetSurfaceRsNode(uint64_t nodeId, std::shared_ptr<Rosen::RSNode> node);
    std::shared_ptr<Rosen::RSNode> GetSurfaceRsNode(uint64_t nodeId) const;
    void RemoveSurfaceRsNode(uint64_t nodeId);

private:
    WebDelegateSurfaceRegistry() = default;

    WebDelegateSurfaceRegistry(const WebDelegateSurfaceRegistry&) = delete;
    WebDelegateSurfaceRegistry& operator=(const WebDelegateSurfaceRegistry&) = delete;

    mutable std::shared_mutex mutex_;
    std::unordered_map<uint64_t, std::shared_ptr<Rosen::RSNode>> nodeMap_;
};

} // namespace OHOS::NWeb

#endif // WEB_WEBVIEW_ARKWEB_UTILS_WEB_SURFACE_REGISTRY_H
