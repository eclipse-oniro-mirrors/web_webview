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

#ifndef PERF_MONITOR_ADAPTER_IMPL_H
#define PERF_MONITOR_ADAPTER_IMPL_H

#include "perf_monitor_adapter.h"

namespace OHOS::NWeb {
class PerfMonitorAdapterImpl : public PerfMonitorAdapter {
public:
    static PerfMonitorAdapterImpl& GetInstance();

    ~PerfMonitorAdapterImpl() override = default;

    void WebComponentLoad(int64_t navigationId) override;

    void WebContentPaintComplete(int64_t navigationId,
                                 int64_t largestContentPaintTime) override;
};
} // namespace OHOS::NWeb

#endif // PERF_MONITOR_ADAPTER_IMPL_H
