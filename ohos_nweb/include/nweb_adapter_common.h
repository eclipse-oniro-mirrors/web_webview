// Copyright (c) 2022 Huawei Device Co., Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NWEB_ADAPTER_COMMON_H
#define NWEB_ADAPTER_COMMON_H

#include <memory>
#include <surface.h>
#include "nweb.h"

namespace OHOS::NWeb {
struct NWebWindowInfo {
    uint32_t width = 0;
    uint32_t height = 0;
    sptr<SurfaceBuffer> cachedSurfaceBuffer = nullptr;
};

struct VsyncCbInfo {
    std::weak_ptr<NWeb> nwebWeak;
};
} // namespace OHOS

#endif // NWEB_ADAPTER_COMMON_H