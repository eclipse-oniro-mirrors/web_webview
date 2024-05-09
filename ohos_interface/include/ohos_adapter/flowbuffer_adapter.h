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

#ifndef FLOWBUFFER_ADAPTER_H
#define FLOWBUFFER_ADAPTER_H

#include <cstdint>
#include <cstdio>

namespace OHOS::NWeb {

class FlowbufferAdapter {
public:
    /**
     * @brief Construct a new FlowbufferAdapter object
     */
    FlowbufferAdapter() = default;

    /**
     * @brief Destroy the FlowbufferAdapter object
     */
    virtual ~FlowbufferAdapter() = default;

    /**
     * @brief Start temporary performance boost when some key tasks are running
     */
    virtual void StartPerformanceBoost();

    /**
     * @brief Create ashmem
     *
     * @param size size of the ashmem to be created
     * @param mapType mapType of the ashmem to be created
     * @param fd fd of the ashmem to be created
     * @return the address of the created ashmem
     */
    virtual void* CreateAshmem(size_t size, int mapType, int& fd);

    /**
     * @brief Create ashmem with fd
     *
     * @param fd fd of the ashmem to be created
     * @param size size of the ashmem to be created
     * @param mapType mapType of the ashmem to be created
     * @return the address of the created ashmem
     */
    virtual void* CreateAshmemWithFd(const int fd, size_t size, int mapType);
};

} // namespace OHOS::NWeb

#endif // FLOWBUFFER_ADAPTER_H
