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

#include "graphic_adapter.h"
#include "vsync_receiver.h"

namespace OHOS::NWeb {
class VSyncAdapterImpl : public VSyncAdapter {
public:
    VSyncAdapterImpl() = default;
    ~VSyncAdapterImpl() override = default;
    VSyncAdapterImpl(const VSyncAdapterImpl&) = delete;
    VSyncAdapterImpl& operator=(const VSyncAdapterImpl&) = delete;

    VSyncErrorCode RequestVsync(void* data, std::function<void(int64_t, void*)> NWebVSyncCb) override;

private:
    std::shared_ptr<Rosen::VSyncReceiver> receiver_ = nullptr;
    std::unique_ptr<Rosen::VSyncReceiver::FrameCallback> frameCb_ = nullptr;
};
} // namespace OHOS::NWeb

#endif // VSYNC_ADAPTER_IMPL_H