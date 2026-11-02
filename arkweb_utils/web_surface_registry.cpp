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
#include "web_surface_registry.h"

#include "nweb_log.h"
#include <cinttypes>

namespace OHOS::NWeb {

WebDelegateSurfaceRegistry& WebDelegateSurfaceRegistry::Instance()
{
    static WebDelegateSurfaceRegistry registry;
    return registry;
}

void WebDelegateSurfaceRegistry::SetSurfaceRsNode(uint64_t nodeId, std::shared_ptr<Rosen::RSNode> node)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    nodeMap_[nodeId] = std::move(node);
    WVLOG_D("DelegateDebug nodeId=%{public}" PRIu64, nodeId);
}

std::shared_ptr<Rosen::RSNode> WebDelegateSurfaceRegistry::GetSurfaceRsNode(uint64_t nodeId) const
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = nodeMap_.find(nodeId);
    if (it == nodeMap_.end()) {
        WVLOG_E("DelegateDebug get node failed, id: %{public}" PRIu64, nodeId);
        return nullptr;
    }
    WVLOG_D("DelegateDebug nodeId=%{public}" PRIu64, nodeId);
    return it->second;
}

void WebDelegateSurfaceRegistry::RemoveSurfaceRsNode(uint64_t nodeId)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    nodeMap_.erase(nodeId);
}

} // namespace OHOS::NWeb
