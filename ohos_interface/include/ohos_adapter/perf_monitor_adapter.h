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

#ifndef PERF_MONITOR_ADAPTER_H
#define PERF_MONITOR_ADAPTER_H

#include <cstdint>

namespace OHOS::NWeb {

class PerfMonitorAdapter {
public:
    PerfMonitorAdapter() = default;

    virtual ~PerfMonitorAdapter() = default;

    virtual void WebComponentLoad(int64_t navigationId) = 0;

    virtual void WebContentPaintComplete(int64_t navigationId,
                                         int64_t largestContentPaintTime) = 0;
};

} // namespace OHOS::NWeb

#endif // PERF_MONITOR_ADAPTER_H
