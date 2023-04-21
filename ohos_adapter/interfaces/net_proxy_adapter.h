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

#ifndef NET_PROXY_ADAPTER_H
#define NET_PROXY_ADAPTER_H

#include <functional>
#include <memory>

namespace OHOS::NWeb {

using NetProxyEventCallback = std::function<void(
    std::string& host, uint16_t& port, const std::string& pac_url, const std::vector<std::string>& exclusionList)>;
class NetProxyAdapter {
public:
    NetProxyAdapter() = default;
    virtual ~NetProxyAdapter() = default;

    virtual void RegNetProxyEvent(const NetProxyEventCallback&& eventCallback) = 0;

    virtual bool StartListen() = 0;

    virtual void StopListen() = 0;

    virtual void GetProperty(std::string& host, uint16_t& port, std::string& pac_url, std::string& exclusion) = 0;
};

} // namespace OHOS::NWeb

#endif // NET_PROXY_ADAPTER_H