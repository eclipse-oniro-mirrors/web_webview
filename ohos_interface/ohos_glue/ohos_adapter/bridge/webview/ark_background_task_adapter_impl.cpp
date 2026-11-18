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

#include "ohos_adapter/bridge/ark_background_task_adapter_impl.h"
#include "ohos_adapter/bridge/ark_background_state_change_callback_adapter_wrapper.h"
#include "background_task_adapter.h"
#include "ohos_adapter/include/ark_background_task_adapter.h"

#include "base/bridge/ark_web_bridge_macros.h"

namespace OHOS::ArkWeb {

bool ArkBackgroundTaskAdapter::RequestBackgroundRunning(bool running, int32_t bgMode)
{
    return NWeb::BackgroundTaskAdapter::RequestBackgroundRunning(running, (NWeb::BackgroundModeAdapter)bgMode);
}

bool ArkBackgroundTaskAdapter::RequestBackgroundRunningWithRenderPids(bool running, int32_t bgMode,
                                                                      const ArkWebInt32Vector& renderPids)
{
    std::vector<int32_t> renderPidList =
        ArkWebBasicVectorStructToClass<int32_t, ArkWebInt32Vector>(renderPids);
    return NWeb::BackgroundTaskAdapter::RequestBackgroundRunningWithRenderPids(
        running, static_cast<NWeb::BackgroundModeAdapter>(bgMode), renderPidList);
}

ArkBackgroundTaskAdapterImpl::ArkBackgroundTaskAdapterImpl(
    std::shared_ptr<OHOS::NWeb::BackgroundTaskAdapter> ref) : real_(ref)
{}

bool ArkBackgroundTaskAdapterImpl::RequestBackgroundTaskRunning(bool running, int32_t bgMode)
{
    return real_->RequestBackgroundTaskRunning(running, (NWeb::BackgroundModeAdapter)bgMode);
}

void ArkBackgroundTaskAdapterImpl::RegisterBackgroundTaskPolicyCallback(
    const ArkWebRefPtr<ArkBackgroundStateChangeCallbackAdapter> callback)
{
    if (CHECK_REF_PTR_IS_NULL(callback)) {
        return ;
    }

    real_->RegisterBackgroundTaskPolicyCallback(
        std::make_shared<ArkBackgroundStateChangeCallbackAdapterWrapper>(callback));
}

bool ArkBackgroundTaskAdapterImpl::RequestBackgroundTaskRunningWithRenderPids(
    bool running, int32_t bgMode, const ArkWebInt32Vector& renderPids)
{
    std::vector<int32_t> renderPidList =
        ArkWebBasicVectorStructToClass<int32_t, ArkWebInt32Vector>(renderPids);
    return real_->RequestBackgroundTaskRunningWithRenderPids(
        running, static_cast<NWeb::BackgroundModeAdapter>(bgMode), renderPidList);
}
} // namespace OHOS::ArkWeb
