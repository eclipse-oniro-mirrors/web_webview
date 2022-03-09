// Copyright (c) 2022 Huawei Device Co., Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NWEB_SURFACE_ADAPTER_H
#define NWEB_SURFACE_ADAPTER_H

#include <unordered_map>
#include "nweb_adapter_common.h"

namespace OHOS {
class Surface;
}

namespace OHOS::NWeb {
class NWebSurfaceAdapter {
public:
    static NWebSurfaceAdapter &Instance();
    NWebCreateInfo GetCreateInfo(sptr<Surface> surface,
                                 const NWebInitArgs &initArgs,
                                 uint32_t width,
                                 uint32_t height);

private:
    void GetSize(sptr<Surface> surface, NWebCreateInfo &createInfo, uint32_t width, uint32_t height) const;
    void GetRenderInterface(sptr<Surface> surface, NWebCreateInfo &createInfo);
    sptr<SurfaceBuffer> RequestBuffer(sptr<Surface> surface, uint32_t width, uint32_t height);
    bool CopyFrame(sptr<SurfaceBuffer> surfaceBuffer, const char *src, uint32_t width, uint32_t height);
    bool FlushBuffer(sptr<Surface> surface, sptr<SurfaceBuffer> surfaceBuffer, uint32_t width, uint32_t height);
};
} // namespace OHOS::NWeb

#endif // NWEB_SURFACE_ADAPTER_H