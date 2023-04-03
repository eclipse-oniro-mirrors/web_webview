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

#ifndef SURFACE_ADAPTER_IMPL_H
#define SURFACE_ADAPTER_IMPL_H

#include "graphic_adapter.h"
#include "ibuffer_consumer_listener.h"
#include "iconsumer_surface.h"

namespace OHOS::NWeb {
class SurfaceBufferAdapterImpl : public SurfaceBufferAdapter {
public:
    explicit SurfaceBufferAdapterImpl(sptr<SurfaceBuffer> buffer);

    ~SurfaceBufferAdapterImpl() override = default;

    int32_t GetFileDescriptor() const override;

    int32_t GetWidth() const override;

    int32_t GetHeight() const override;

    int32_t GetStride() const override;

    int32_t GetFormat() const override;

    uint32_t GetSize() const override;

    sptr<SurfaceBuffer>& GetBuffer();

private:
    sptr<SurfaceBuffer> buffer_ = nullptr;
};

class BufferConsumerListenerImpl : public IBufferConsumerListener {
public:
    BufferConsumerListenerImpl(
        wptr<IConsumerSurface> surface, std::unique_ptr<IBufferConsumerListenerAdapter> listener);

    ~BufferConsumerListenerImpl() override = default;

    void OnBufferAvailable() override;

private:
    wptr<IConsumerSurface> cSurface_ = nullptr;

    std::unique_ptr<IBufferConsumerListenerAdapter> listener_ = nullptr;
};

class ConsumerSurfaceAdapterImpl : public IConsumerSurfaceAdapter {
public:
    ConsumerSurfaceAdapterImpl();

    ~ConsumerSurfaceAdapterImpl() = default;

    int32_t RegisterConsumerListener(std::unique_ptr<IBufferConsumerListenerAdapter> listenerAdapter) override;

    int32_t ReleaseBuffer(std::unique_ptr<SurfaceBufferAdapter> bufferAdapter, int32_t fence) override;

    int32_t SetUserData(const std::string& key, const std::string& val) override;

    int32_t SetQueueSize(uint32_t queueSize) override;

    sptr<IConsumerSurface>& GetConsumerSurface();

private:
    sptr<IConsumerSurface> cSurface_ = nullptr;
};
} // namespace OHOS::NWeb

#endif // SURFACE_ADAPTER_IMPL_H
