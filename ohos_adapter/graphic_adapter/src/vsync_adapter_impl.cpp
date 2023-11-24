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

#include "vsync_adapter_impl.h"

#include "nweb_log.h"
#include "res_sched_client_adapter.h"
#include "transaction/rs_interfaces.h"

namespace OHOS::NWeb {
namespace {
const std::string THREAD_NAME = "VSync-webview";
}

VSyncAdapterImpl::~VSyncAdapterImpl()
{
    if (vsyncHandler_) {
        vsyncHandler_->RemoveAllEvents();
        auto runner = vsyncHandler_->GetEventRunner();
        if (runner) {
            runner->Stop();
            ResSchedClientAdapter::ReportKeyThread(ResSchedStatusAdapter::THREAD_DESTROYED,
                getpid(), runner->GetKernelThreadId(), ResSchedRoleAdapter::IMPORTANT_DISPLAY);
        }
        vsyncHandler_ = nullptr;
    }
    hasReportedKeyThread_ = false;
}

VSyncAdapterImpl& VSyncAdapterImpl::GetInstance()
{
    static VSyncAdapterImpl instance;
    return instance;
}

VSyncErrorCode VSyncAdapterImpl::Init()
{
    if (!receiver_) {
        if (!vsyncHandler_) {
            std::shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::Create(THREAD_NAME);
            vsyncHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
            runner->Run();
        }
        auto& rsClient = OHOS::Rosen::RSInterfaces::GetInstance();
        receiver_ = rsClient.CreateVSyncReceiver("NWeb_" + std::to_string(::getpid()), vsyncHandler_);
        if (!receiver_) {
            WVLOG_E("CreateVSyncReceiver failed");
            return VSyncErrorCode::ERROR;
        }
        VsyncError ret = receiver_->Init();
        if (ret != VsyncError::GSERROR_OK) {
            receiver_ = nullptr;
            WVLOG_E("vsync receiver init failed, ret=%{public}d", ret);
            return VSyncErrorCode::ERROR;
        }
    }
    return VSyncErrorCode::SUCCESS;
}

VSyncErrorCode VSyncAdapterImpl::RequestVsync(void* data, std::function<void(int64_t, void*)> NWebVSyncCb)
{
    if (Init() != VSyncErrorCode::SUCCESS) {
        WVLOG_E("NWebWindowAdapter init fail");
        return VSyncErrorCode::ERROR;
    }

    if (!hasReportedKeyThread_) {
        auto runner = vsyncHandler_->GetEventRunner();
        // At this point, the threadId corresponding to eventrunner may not be available,
        // so need to confirm it several times
        if (runner && runner->GetKernelThreadId() != 0) {
            ResSchedClientAdapter::ReportKeyThread(ResSchedStatusAdapter::THREAD_CREATED,
                getpid(), runner->GetKernelThreadId(), ResSchedRoleAdapter::IMPORTANT_DISPLAY);
            hasReportedKeyThread_ = true;
        }
    }

    std::lock_guard<std::mutex> lock(mtx_);
    vsyncCallbacks_.insert({data, NWebVSyncCb});

    if (hasRequestedVsync_) {
        return VSyncErrorCode::SUCCESS;
    }

    VsyncError ret = receiver_->RequestNextVSync(frameCallback_);
    if (ret != VsyncError::GSERROR_OK) {
        WVLOG_E("NWebWindowAdapter RequestNextVSync fail, ret=%{public}d", ret);
        return VSyncErrorCode::ERROR;
    }
    hasRequestedVsync_ = true;
    return VSyncErrorCode::SUCCESS;
}

void VSyncAdapterImpl::OnVsync(int64_t timestamp, void* client)
{
    auto vsyncClient = static_cast<VSyncAdapterImpl*>(client);
    if (vsyncClient) {
        vsyncClient->VsyncCallbackInner(timestamp);
    } else {
        WVLOG_E("VsyncClient is null");
    }
}

void VSyncAdapterImpl::VsyncCallbackInner(int64_t timestamp)
{
    std::unordered_map<void*, std::function<void(int64_t, void*)>> vsyncCallbacks;
    std::lock_guard<std::mutex> lock(mtx_);
    vsyncCallbacks = vsyncCallbacks_;
    vsyncCallbacks_.clear();

    for (const auto& callback : vsyncCallbacks) {
        auto func = callback.second;
        if (func) {
            func(timestamp, callback.first);
        }
    }
    hasRequestedVsync_ = false;
}

int64_t VSyncAdapterImpl::GetVSyncPeriod()
{
    int64_t period = 0;
    if (Init() != VSyncErrorCode::SUCCESS) {
        WVLOG_E("NWebWindowAdapter init fail");
        return period;
    }

    VsyncError ret = receiver_->GetVSyncPeriod(period);
    if (ret != VsyncError::GSERROR_OK) {
        WVLOG_E("NWebWindowAdapter GetVSyncPeriod fail, ret=%{public}d", ret);
    }
    return period;
}
} // namespace OHOS::NWeb