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

#ifndef ARK_WINDOW_ADAPTER_WRAPPER_H
#define ARK_WINDOW_ADAPTER_WRAPPER_H
#pragma once

#include "graphic_adapter.h"
#include "ohos_adapter/include/ark_graphic_adapter.h"

namespace OHOS::ArkWeb {

using ArkWebNativeWindow = OHOS::NWeb::NWebNativeWindow;

class ArkWindowAdapterWrapper : public OHOS::NWeb::WindowAdapter {
public:
    explicit ArkWindowAdapterWrapper(ArkWebRefPtr<ArkWindowAdapter>);

    ArkWebNativeWindow CreateNativeWindowFromSurface(void* pSurface) override;

    void DestroyNativeWindow(ArkWebNativeWindow window) override;

    int32_t NativeWindowSetBufferGeometry(ArkWebNativeWindow window, int32_t width, int32_t height) override;

    void NativeWindowSurfaceCleanCache(ArkWebNativeWindow window) override;

    void NativeWindowSurfaceCleanCacheWithPara(ArkWebNativeWindow window, bool cleanAll) override;
private:
    ArkWebRefPtr<ArkWindowAdapter> ctocpp_;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WINDOW_ADAPTER_WRAPPER_H