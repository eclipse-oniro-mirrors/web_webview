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

#ifndef VSYNC_ADAPTER_IMPL_H
#define VSYNC_ADAPTER_IMPL_H

#include <functional>
#include <memory>

#include "event_handler.h"
#include "graphic_adapter.h"
#include "vsync_receiver.h"
#include "foundation/graphic/graphic_2d/rosen/modules/render_service_client/core/ui/rs_frame_rate_linker.h"

namespace OHOS::NWeb {
class VSyncAdapterImpl : public VSyncAdapter {
public:
    VSyncAdapterImpl() = default;
    ~VSyncAdapterImpl() override;
    VSyncAdapterImpl(const VSyncAdapterImpl&) = delete;
    VSyncAdapterImpl& operator=(const VSyncAdapterImpl&) = delete;

    static VSyncAdapterImpl& GetInstance();
    VSyncErrorCode RequestVsync(void* data, NWebVSyncCb cb) override;
    int64_t GetVSyncPeriod() override;
    void SetFrameRateLinkerEnable(bool enabled) override;
    void SetFramePreferredRate(int32_t preferredRate) override;

    void SetOnVsyncCallback(void (*callback)()) override;
private:
    static void OnVsync(int64_t timestamp, void* data);
    void VsyncCallbackInner(int64_t nanoTimestamp);
    VSyncErrorCode Init();

    std::mutex mtx_;
    bool hasRequestedVsync_ = false;
    bool hasReportedKeyThread_ = false;
    std::shared_ptr<Rosen::VSyncReceiver> receiver_ = nullptr;
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> vsyncHandler_;
    std::unordered_map<void*, NWebVSyncCb> vsyncCallbacks_;
    Rosen::VSyncReceiver::FrameCallback frameCallback_ = {
        .userData_ = this,
        .callback_ = OnVsync,
    };
    std::shared_ptr<Rosen::RSFrameRateLinker> frameRateLinker_;
    static void (*callback_)();
    bool frameRateLinkerEnable_ = false;
};
} // namespace OHOS::NWeb

#endif // VSYNC_ADAPTER_IMPL_H
