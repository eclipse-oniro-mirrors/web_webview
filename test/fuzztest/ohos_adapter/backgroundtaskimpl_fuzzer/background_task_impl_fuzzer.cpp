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

#include "background_task_impl_fuzzer.h"
#include <cstdint>
#include <unistd.h>
#include <memory>
#include <vector>
#include "background_task_adapter.h"
#include "background_task_impl.h"

using namespace OHOS::NWeb;
namespace {
  constexpr size_t RENDER_PID_DATA_INDEX = 2;
  constexpr size_t MIN_SIZE_WITH_RENDER_PID = 3;
}
class BackgroundStateChangeCallbackAdapterMock : public BackgroundStateChangeCallbackAdapter {
public:
    BackgroundStateChangeCallbackAdapterMock() = default;
    void NotifyApplicationForeground() {}
    void NotifyApplicationBackground() {}
};

namespace OHOS {
    bool BackgroundTaskRequestFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size < sizeof(bool) + sizeof(BackgroundModeAdapter))) {
            return false;
        }

        bool running = static_cast<bool>(data[0]);
        BackgroundModeAdapter bgMode = static_cast<BackgroundModeAdapter>(data[1]);
        BackgroundTaskAdapter::RequestBackgroundRunning(running, bgMode);

        std::shared_ptr<BackgroundStateChangeCallbackAdapter> callback =
            std::make_shared<BackgroundStateChangeCallbackAdapterMock>();
        std::shared_ptr<BackgroundTaskAdapterImpl> adapter =
            std::make_shared<BackgroundTaskAdapterImpl>();
        adapter->RegisterBackgroundTaskPolicyCallback(callback);
        adapter->RequestBackgroundTaskRunning(running, bgMode);
        // Fuzz RequestBackgroundRunningWithRenderPids / RequestBackgroundTaskRunningWithRenderPids.
        if (size >= MIN_SIZE_WITH_RENDER_PID) { // data[2]: render pid
            std::vector<int32_t> renderPids;
            renderPids.emplace_back(static_cast<int32_t>(data[RENDER_PID_DATA_INDEX]));
            BackgroundTaskAdapter::RequestBackgroundRunningWithRenderPids(running, bgMode, renderPids);
            adapter->RequestBackgroundTaskRunningWithRenderPids(running, bgMode, renderPids);
        }
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::BackgroundTaskRequestFuzzTest(data, size);
    return 0;
}