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

#include "surface_adapter_impl.h"

#include "drivers/peripheral/display/interfaces/include/display_type.h"
#include "nweb_log.h"

namespace OHOS::NWeb {
namespace {
bool IsSupportFormat(int32_t format)
{
    switch (format) {
        case PixelFormat::PIXEL_FMT_RGBA_8888:
        case PixelFormat::PIXEL_FMT_YCBCR_420_SP:
            return true;
        default:
            return false;
    }
}
} // namespace

const int32_t GSErrorCode::GSERROR_OK = GSError::GSERROR_OK;

const int32_t PixelFormatAdapter::PIXEL_FMT_RGBA_8888 = PixelFormat::PIXEL_FMT_RGBA_8888;

const int32_t PixelFormatAdapter::PIXEL_FMT_YCBCR_420_SP = PixelFormat::PIXEL_FMT_YCBCR_420_SP;

SurfaceBufferAdapterImpl::SurfaceBufferAdapterImpl(sptr<SurfaceBuffer> buffer) : buffer_(buffer) {}

int32_t SurfaceBufferAdapterImpl::GetFileDescriptor() const
{
    if (!buffer_) {
        WVLOG_E("buffer_ is nullptr");
        return -1;
    }
    return buffer_->GetFileDescriptor();
}

int32_t SurfaceBufferAdapterImpl::GetWidth() const
{
    if (!buffer_) {
        WVLOG_E("buffer_ is nullptr");
        return -1;
    }
    return buffer_->GetWidth();
}

int32_t SurfaceBufferAdapterImpl::GetHeight() const
{
    if (!buffer_) {
        WVLOG_E("buffer_ is nullptr");
        return -1;
    }
    return buffer_->GetHeight();
}

int32_t SurfaceBufferAdapterImpl::GetStride() const
{
    if (!buffer_) {
        WVLOG_E("buffer_ is nullptr");
        return -1;
    }
    return buffer_->GetStride();
}

int32_t SurfaceBufferAdapterImpl::GetFormat() const
{
    if (!buffer_) {
        WVLOG_E("buffer_ is nullptr");
        return -1;
    }
    return buffer_->GetFormat();
}

uint32_t SurfaceBufferAdapterImpl::GetSize() const
{
    if (!buffer_) {
        WVLOG_E("buffer_ is nullptr");
        return 0;
    }
    return buffer_->GetSize();
}

void *SurfaceBufferAdapterImpl::GetVirAddr() const
{
    if (!buffer_) {
        WVLOG_E("buffer_ is nullptr");
        return nullptr;
    }
    return buffer_->GetVirAddr();
}

sptr<SurfaceBuffer>& SurfaceBufferAdapterImpl::GetBuffer()
{
    return buffer_;
}

BufferConsumerListenerImpl::BufferConsumerListenerImpl(
    wptr<IConsumerSurface> surface, std::unique_ptr<IBufferConsumerListenerAdapter> listener)
    : cSurface_(surface), listener_(std::move(listener))
{}

void BufferConsumerListenerImpl::OnBufferAvailable()
{
    if (cSurface_ == nullptr || listener_ == nullptr) {
        WVLOG_E("cSurface_ or listener_ is nullptr");
        return;
    }
    auto surfaceTemp = cSurface_.promote();
    if (surfaceTemp == nullptr) {
        WVLOG_E("surface is nullptr");
        return;
    }
    sptr<SurfaceBuffer> buffer;
    int32_t fence;
    int64_t timestamp;
    Rect damage;
    GSError ret = surfaceTemp->AcquireBuffer(buffer, fence, timestamp, damage);
    if (ret != GSERROR_OK) {
        WVLOG_E("acquire buffer failed, ret=%{public}d", ret);
        return;
    }
    int32_t format = buffer->GetFormat();
    if (!IsSupportFormat(format)) {
        WVLOG_E("unsupport format for:%{public}d", format);
        surfaceTemp->ReleaseBuffer(buffer, -1);
        return;
    }
    auto bufferAdapter = std::make_unique<SurfaceBufferAdapterImpl>(buffer);
    listener_->OnBufferAvailable(std::move(bufferAdapter));
}

ConsumerSurfaceAdapterImpl::ConsumerSurfaceAdapterImpl() : cSurface_(IConsumerSurface::Create()) {}

int32_t ConsumerSurfaceAdapterImpl::RegisterConsumerListener(
    std::unique_ptr<IBufferConsumerListenerAdapter> listenerAdapter)
{
    if (!cSurface_ || !listenerAdapter) {
        WVLOG_E("cSurface_ or listener_ is nullptr");
        return -1;
    }
    sptr<IBufferConsumerListener> listener =
        new (std::nothrow) BufferConsumerListenerImpl(cSurface_, std::move(listenerAdapter));
    if (!listener) {
        WVLOG_E("listener create failed");
        return -1;
    }
    return cSurface_->RegisterConsumerListener(listener);
}

int32_t ConsumerSurfaceAdapterImpl::ReleaseBuffer(std::unique_ptr<SurfaceBufferAdapter> bufferAdapter, int32_t fence)
{
    if (!cSurface_ || !bufferAdapter) {
        WVLOG_E("cSurface_ or bufferAdapter is nullptr");
        return -1;
    }
    auto bufferImpl = static_cast<SurfaceBufferAdapterImpl*>(bufferAdapter.get());
    return cSurface_->ReleaseBuffer(bufferImpl->GetBuffer(), fence);
}

int32_t ConsumerSurfaceAdapterImpl::SetUserData(const std::string& key, const std::string& val)
{
    if (!cSurface_) {
        WVLOG_E("cSurface_ is nullptr");
        return -1;
    }
    return cSurface_->SetUserData(key, val);
}

int32_t ConsumerSurfaceAdapterImpl::SetQueueSize(uint32_t queueSize)
{
    if (!cSurface_) {
        WVLOG_E("cSurface_ is nullptr");
        return -1;
    }
    return cSurface_->SetQueueSize(queueSize);
}

sptr<IConsumerSurface>& ConsumerSurfaceAdapterImpl::GetConsumerSurface()
{
    return cSurface_;
}
} // namespace OHOS::NWeb
