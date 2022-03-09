// Copyright (c) 2022 Huawei Device Co., Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NWEB_WINDOW_ADAPTER_H
#define NWEB_WINDOW_ADAPTER_H

#include <unordered_map>
#include "nweb_adapter_common.h"
#include "window.h"

namespace OHOS::NWeb {
class NWebWindowAdapter {
public:
    static NWebWindowAdapter &Instance();
    NWebCreateInfo GetCreateInfo(Rosen::Window *window, const  NWebInitArgs &initArgs);
    void RegistEventCb(Rosen::Window *window, std::shared_ptr<NWeb> nweb);
    void RequestVsync(Rosen::Window *window, std::shared_ptr<NWeb> nweb);

private:
    void GetSize(Rosen::Window *window, NWebCreateInfo &createInfo);
    void GetRenderInterface(Rosen::Window *window, NWebCreateInfo &createInfo);
    void VsyncCb(Rosen::Window *window, std::shared_ptr<NWeb> nweb);

private:
    std::unordered_map<Rosen::Window *, NWebWindowInfo> windowInfoMap_;
};
} // namespace OHOS

#endif // NWEB_WINDOW_ADAPTER_H