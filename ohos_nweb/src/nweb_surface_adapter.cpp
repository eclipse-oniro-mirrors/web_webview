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

#include "nweb_surface_adapter.h"

#include <securec.h>
#include <display_type.h>
#include <ui/rs_surface_node.h>
#include <sync_fence.h>
#include "nweb_log.h"
 
namespace {
constexpr int BITS_PER_PIXEL = 4;
}

namespace OHOS::NWeb {
NWebSurfaceAdapter &NWebSurfaceAdapter::Instance()
{
    static NWebSurfaceAdapter surfaceAdapter;
    return surfaceAdapter;
}

NWebCreateInfo NWebSurfaceAdapter::GetCreateInfo(sptr<Surface> surface,
                                                 const NWebInitArgs &initArgs,
                                                 uint32_t width,
                                                 uint32_t height)
{
    NWebCreateInfo createInfo = {
        .init_args = initArgs,
    };
    if (surface == nullptr) {
        return createInfo;
    }
    GetSize(surface, createInfo, width, height);
    GetRenderInterface(surface, createInfo);
    return createInfo;
}

void NWebSurfaceAdapter::GetSize(sptr<Surface> surface,
                                 NWebCreateInfo &createInfo,
                                 uint32_t width,
                                 uint32_t height) const
{
    if (surface == nullptr) {
        return;
    }
    createInfo.width = (width == 0) ? surface->GetDefaultWidth() : width;
    createInfo.height = (height == 0) ? surface->GetDefaultHeight() : height;
}

void NWebSurfaceAdapter::GetRenderInterface(sptr<Surface> surface, NWebCreateInfo &createInfo)
{
    wptr<Surface> surfaceWeak(surface);
    createInfo.output_render_frame = [surfaceWeak, this] (const char *buffer, uint32_t width, uint32_t height) -> bool {
        sptr<Surface> surface = surfaceWeak.promote();
        if (surface == nullptr) {
            WVLOG_E("surface is nullptr or has expired");
            return false;
        }

        sptr<SurfaceBuffer> surfaceBuffer = this->RequestBuffer(surface, width, height);
        if (surfaceBuffer == nullptr) {
            return false;
        }

        if (!this->CopyFrame(surfaceBuffer, buffer, width, height)) {
            surface->CancelBuffer(surfaceBuffer);
            return false;
        }

        return this->FlushBuffer(surface, surfaceBuffer, width, height);
    };
}

sptr<SurfaceBuffer> NWebSurfaceAdapter::RequestBuffer(sptr<Surface> surface, uint32_t width, uint32_t height)
{
    if (surface == nullptr) {
        return nullptr;
    }

    BufferRequestConfig config = {
        .width = width,
        .height = height,
        .strideAlignment = sizeof(void *),
        .format = PIXEL_FMT_RGBA_8888,
        .usage = HBM_USE_CPU_READ | HBM_USE_CPU_WRITE | HBM_USE_MEM_DMA,
        .timeout = 0,
    };

    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    int32_t releaseFence = -1;
    SurfaceError ret = surface->RequestBuffer(surfaceBuffer, releaseFence, config);
    if (ret != SURFACE_ERROR_OK) {
        WVLOG_E("fail to request buffer from surface, errorcode=%{public}d", ret);
        return nullptr;
    }

    sptr<SyncFence> tempFence = new SyncFence(releaseFence);
    tempFence->Wait(100); // 100 ms

    return surfaceBuffer;
}

bool NWebSurfaceAdapter::CopyFrame(
    sptr<SurfaceBuffer> surfaceBuffer, const char *src, uint32_t width, uint32_t height)
{
    if (surfaceBuffer == nullptr) {
        return false;
    }

    char *dst = reinterpret_cast<char *>(surfaceBuffer->GetVirAddr());
    if (dst == nullptr) {
        WVLOG_E("fail to get buffer addr");
        return false;
    }
 
    uint32_t srcStride = width * BITS_PER_PIXEL;
    uint32_t dstStride = surfaceBuffer->GetStride();
    uint32_t copiedSize = 0;
 
    for (uint32_t currHeight = 0; currHeight < height; ++currHeight) {
        if (copiedSize + dstStride > surfaceBuffer->GetSize()) {
            WVLOG_E("copy size overflow, drop this frame(%{public}u*%{public}u)", width, height);
            return false;
        }
        errno_t ret = memcpy_s(dst, static_cast<size_t>(srcStride), src, static_cast<size_t>(srcStride));
        if (ret != EOK) {
            WVLOG_E("memcpy_s failed");
            return false;
        }
        src += srcStride;
        dst += dstStride;
        copiedSize += dstStride;
    }

    return true;
}

bool NWebSurfaceAdapter::FlushBuffer(
    sptr<Surface> surface, sptr<SurfaceBuffer> surfaceBuffer, uint32_t width, uint32_t height)
{
    if (surface == nullptr) {
        return false;
    }

    BufferFlushConfig flushConfig = {
        .damage = {
            .w = width,
            .h = height,
        },
        .timestamp = 0,
    };

    SurfaceError ret = surface->FlushBuffer(surfaceBuffer, -1, flushConfig);
    if (ret != SURFACE_ERROR_OK) {
        WVLOG_E("FAIL flush nweb render frame, ret=%{public}d", ret);
        return false;
    }

    return true;
}
} // namespace OHOS::NWeb
