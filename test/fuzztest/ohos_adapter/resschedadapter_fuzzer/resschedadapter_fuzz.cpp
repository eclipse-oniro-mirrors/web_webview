/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "resschedadapter_fuzz.h"
#include "res_sched_client_adapter.h"

#include <cstring>
#include <securec.h>

using namespace OHOS::NWeb;

namespace OHOS {
    bool ResSchedAdapterFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }
        int32_t windowId = 0;
        int32_t nwebId = 0;
        pid_t pid = 0;
        ResSchedClientAdapter resSchedClientAdapter;
        resSchedClientAdapter.ReportVideoPlaying(ResSchedStatusAdapter::WEB_ACTIVE, pid);
        resSchedClientAdapter.ReportScreenCapture(ResSchedStatusAdapter::WEB_ACTIVE, pid);
        resSchedClientAdapter.ReportRenderProcessStatus(ResSchedStatusAdapter::WEB_ACTIVE, pid);
        resSchedClientAdapter.ReportNWebInit(ResSchedStatusAdapter::WEB_ACTIVE, nwebId);
        resSchedClientAdapter.ReportWindowId(windowId, nwebId);
        resSchedClientAdapter.ReportScene(
            ResSchedStatusAdapter::WEB_ACTIVE, ResSchedSceneAdapter::KEYBOARD_CLICK, nwebId);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::ResSchedAdapterFuzzTest(data, size);
    return 0;
}
