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
#include "transaction/rs_interfaces.h"

namespace OHOS::NWeb {
VSyncErrorCode VSyncAdapterImpl::RequestVsync(void* data, std::function<void(int64_t, void*)> NWebVSyncCb)
{
    if (!receiver_) {
        auto& rsClient = OHOS::Rosen::RSInterfaces::GetInstance();
        receiver_ = rsClient.CreateVSyncReceiver("NWeb_" + std::to_string(::getpid()));
        if (!receiver_) {
            WVLOG_E("CreateVSyncReceiver failed");
            return VSyncErrorCode::ERROR;
        }
        VsyncError ret = receiver_->Init();
        if (ret != VsyncError::GSERROR_OK) {
            WVLOG_E("vsync receiver init failed, ret=%{public}d", ret);
            receiver_ = nullptr;
            return VSyncErrorCode::ERROR;
        }

        frameCb_ = std::make_unique<Rosen::VSyncReceiver::FrameCallback>();
        if (!frameCb_) {
            WVLOG_E("vsync frame callback make failed");
            receiver_ = nullptr;
            return VSyncErrorCode::ERROR;
        }
        frameCb_->userData_ = data;
        frameCb_->callback_ = NWebVSyncCb;
    }

    int ret = receiver_->RequestNextVSync(*frameCb_);
    if (ret != VsyncError::GSERROR_OK) {
        WVLOG_E("NWebWindowAdapter RequestVsync RequestNextVSync fail, ret=%{public}d", ret);
        return VSyncErrorCode::ERROR;
    }
    return VSyncErrorCode::SUCCESS;
}
} // namespace OHOS::NWeb