// Copyright (c) 2022 Huawei Device Co., Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "nweb_window_adapter.h"

#include <securec.h>
#include <surface.h>
#include <vsync_helper.h>
#include <display_type.h>
#include <ui/rs_surface_node.h>
#include "nweb_log.h"
#include "nweb_input_event_consumer.h"

namespace OHOS::NWeb {
// static
NWebWindowAdapter &NWebWindowAdapter::Instance()
{
    static NWebWindowAdapter windowAdapter;
    return windowAdapter;
}

NWebCreateInfo NWebWindowAdapter::GetCreateInfo(Rosen::Window *window, const NWebInitArgs &initArgs)
{
    NWebCreateInfo createInfo = {
        .init_args = initArgs,
    };
    if (window == nullptr) {
        return createInfo;
    }
    GetSize(window, createInfo);
    GetRenderInterface(window, createInfo);
    return createInfo;
}

void NWebWindowAdapter::GetSize(Rosen::Window *window, NWebCreateInfo &createInfo)
{
    createInfo.width = window->GetRect().width_;
    createInfo.height = window->GetRect().height_;
    windowInfoMap_[window].width = createInfo.width;
    windowInfoMap_[window].height = createInfo.height;
}

void NWebWindowAdapter::GetRenderInterface(Rosen::Window *window, NWebCreateInfo &createInfo)
{
    createInfo.output_render_frame = [window, this] (const char *buffer, uint32_t width, uint32_t height) -> bool {
        if (windowInfoMap_[window].cachedSurfaceBuffer != nullptr) {
            WVLOG_I("last cached frame is not consumed, skip this frame output");
            return false;
        }

        sptr<Surface> surface = window->GetSurfaceNode()->GetSurface();
        if (surface == nullptr) {
            WVLOG_E("surface get from window is nullptr");
            return false;
        }

        BufferRequestConfig config = {
            .width = window->GetRect().width_,
            .height = window->GetRect().height_,
            .strideAlignment = sizeof(void *),
            .format = PIXEL_FMT_RGBA_8888,
            .usage = HBM_USE_CPU_READ | HBM_USE_CPU_WRITE | HBM_USE_MEM_DMA,
            .timeout = 0,
        };

        sptr<SurfaceBuffer> surfaceBuffer;
        int32_t releaseFence = -1;
        SurfaceError ret = surface->RequestBuffer(surfaceBuffer, releaseFence, config);
        if (ret != SURFACE_ERROR_OK) {
            WVLOG_E("fail to request buffer from surface, errorcode=%{public}d", ret);
            return false;
        }

        char *addr = reinterpret_cast<char *>(surfaceBuffer->GetVirAddr());
        if (addr == nullptr) {
            WVLOG_E("fail to get buffer addr");
            surface->CancelBuffer(surfaceBuffer);
            return false;
        }

        constexpr uint32_t BITS_PER_PIXEL = 4;
        uint32_t frameSize = windowInfoMap_[window].width * windowInfoMap_[window].height * BITS_PER_PIXEL;
        if (windowInfoMap_[window].width != window->GetRect().width_ ||
            windowInfoMap_[window].height != window->GetRect().height_) {
            WVLOG_W("nweb output frame size (%{public}u*%{public}u) is different from "
                    "window surface buffer size (%{public}u*%{public}u)",
                    windowInfoMap_[window].width, windowInfoMap_[window].height,
                    window->GetRect().width_, window->GetRect().height_);
            uint32_t surfaceBufferSize = window->GetRect().width_ * window->GetRect().height_ * BITS_PER_PIXEL;
            if (surfaceBufferSize < frameSize) {
                frameSize = surfaceBufferSize;
            }
        }
        if (memcpy_s(addr, frameSize, buffer, frameSize) != EOK) {
            WVLOG_E("memcpy_s fail, errorcode=%{public}d", ret);
            return false;
        }

        windowInfoMap_[window].cachedSurfaceBuffer = surfaceBuffer;

        return true;
    };
}

void NWebWindowAdapter::RequestVsync(Rosen::Window *window, std::shared_ptr<NWeb> nweb)
{
    if (window == nullptr) {
        return;
    }

    std::weak_ptr<NWeb> nwebWeak(nweb);
    VsyncCbInfo *info = new(std::nothrow) VsyncCbInfo { nwebWeak };
    if (info == nullptr) {
        return;
    }
    FrameCallback frameCb = {
        .timestamp_ = 0,
        .userdata_ = reinterpret_cast<void *>(info),
        .callback_ = [window, this] (int64_t time, void *userdata) -> void {
            VsyncCbInfo *info = reinterpret_cast<VsyncCbInfo *>(userdata);
            std::weak_ptr<NWeb> nwebWeak = info->nwebWeak;
            delete info;
            info = nullptr;
            if (nwebWeak.expired()) {
                WVLOG_I("nweb instance has expired, stop request vsync");
                return;
            }
            this->VsyncCb(window, nwebWeak.lock());
        },
    };

    VsyncError ret = VsyncHelper::Current()->RequestFrameCallback(frameCb);
    if (ret != VSYNC_ERROR_OK) {
        WVLOG_E("FAIL to request frame callback for nweb render, ret=%{public}d", ret);
    }
}

void NWebWindowAdapter::VsyncCb(Rosen::Window *window, std::shared_ptr<NWeb> nweb)
{
    if (window == nullptr) {
        return;
    }

    if (windowInfoMap_[window].cachedSurfaceBuffer == nullptr) {
        RequestVsync(window, nweb);
        return;
    }

    sptr<Surface> surface = window->GetSurfaceNode()->GetSurface();
    if (surface == nullptr) {
        WVLOG_E("surface get from window is nullptr");
        RequestVsync(window, nweb);
        return;
    }

    BufferFlushConfig flushConfig = {
        .damage = {
            .w = window->GetRect().width_,
            .h = window->GetRect().height_,
        },
        .timestamp = 0,
    };

    SurfaceError ret = surface->FlushBuffer(windowInfoMap_[window].cachedSurfaceBuffer, -1, flushConfig);
    if (ret == SURFACE_ERROR_OK) {
        windowInfoMap_[window].cachedSurfaceBuffer = nullptr;
    } else {
        WVLOG_E("FAIL flush nweb render frame to window surface, ret=%{public}d", ret);
    }

    RequestVsync(window, nweb);
}

void NWebWindowAdapter::RegistEventCb(Rosen::Window *window, std::shared_ptr<NWeb> nweb)
{
    if (window == nullptr) {
        return;
    }

    std::shared_ptr<MMI::IInputEventConsumer> inputEventListener =
        std::make_shared<NWebInputEventConsumer>(nweb);

    window->AddInputEventListener(inputEventListener);
}
} // namespace OHOS::NWeb
