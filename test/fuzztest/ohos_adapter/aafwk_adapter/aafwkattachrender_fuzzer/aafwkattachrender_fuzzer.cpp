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

#include "aafwkattachrender_fuzzer.h"

#include <cstring>
#include <securec.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "aafwk_app_mgr_client_adapter_impl.h"
#include "aafwk_render_scheduler_impl.h"

using namespace OHOS::NWeb;
using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr uint8_t MAX_STRING_LENGTH = 255;

bool AafwkAttachRenderFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    AafwkAppMgrClientAdapterImpl render;
    std::shared_ptr<AafwkRenderSchedulerHostAdapter> adapter = nullptr;
    render.AttachRenderProcess(adapter);
    std::shared_ptr<AafwkAppMgrClientAdapterImpl> newadapter = std::make_shared<AafwkAppMgrClientAdapterImpl>();

    FuzzedDataProvider dataProvider(data, size);
    std::string renderParam = dataProvider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    int32_t ipcFd = 0;
    int32_t sharedFd = 0;
    int32_t crashFd = 0;
    pid_t renderPid = 0;
    newadapter->StartRenderProcess(renderParam, ipcFd, sharedFd, crashFd, renderPid);
    pid_t red = 1;
    int statused = 1;
    newadapter->GetRenderProcessTerminationStatus(red, statused);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AafwkAttachRenderFuzzTest(data, size);
    return 0;
}
