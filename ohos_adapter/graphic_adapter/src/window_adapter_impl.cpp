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

#include "window_adapter_impl.h"

#include <cstdarg>

#include "nweb_log.h"
#include "foundation/graphic/graphic_surface/interfaces/inner_api/surface/window.h"

namespace OHOS::NWeb {
const int32_t WindowAdapter::SET_BUFFER_GEOMETRY = NativeWindowOperation::SET_BUFFER_GEOMETRY;

WindowAdapterImpl& WindowAdapterImpl::GetInstance()
{
    static WindowAdapterImpl instance;
    return instance;
}

NWebNativeWindow WindowAdapterImpl::CreateNativeWindowFromSurface(void* pSurface)
{
    OHNativeWindow* window = ::CreateNativeWindowFromSurface(pSurface);
    return reinterpret_cast<NWebNativeWindow>(window);
}

void WindowAdapterImpl::DestroyNativeWindow(NWebNativeWindow window)
{
    ::DestoryNativeWindow(reinterpret_cast<OHNativeWindow*>(window));
}

int32_t WindowAdapterImpl::NativeWindowHandleOpt(NWebNativeWindow window, int code, ...)
{
    va_list args;
    va_start(args, code);
    int32_t ret = -1;
    switch (code) {
        case SET_BUFFER_GEOMETRY: {
            int32_t width = va_arg(args, int32_t);
            int32_t height = va_arg(args, int32_t);
            ret = ::NativeWindowHandleOpt(reinterpret_cast<OHNativeWindow*>(window), code, width, height);
            break;
        }
        default:
            WVLOG_E("Unsupport parameter format");
            break;
    }
    va_end(args);
    return ret;
}
} // namespace OHOS::NWeb
