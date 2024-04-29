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

#ifndef ARK_AAFWK_RENDER_SCHEDULER_HOST_ADAPTER_WRAPPER_H
#define ARK_AAFWK_RENDER_SCHEDULER_HOST_ADAPTER_WRAPPER_H
#pragma once

#include "aafwk_render_scheduler_host_adapter.h"
#include "ohos_adapter/include/ark_aafwk_render_scheduler_host_adapter.h"

#include "base/include/ark_web_types.h"

namespace OHOS::ArkWeb {

class ArkAafwkRenderSchedulerHostAdapterWrapper : public OHOS::NWeb::AafwkRenderSchedulerHostAdapter {
public:
    ArkAafwkRenderSchedulerHostAdapterWrapper(ArkWebRefPtr<ArkAafwkRenderSchedulerHostAdapter>);

    void NotifyBrowserFd(int32_t ipcFd, int32_t sharedFd, int32_t crashFd) override;

private:
    ArkWebRefPtr<ArkAafwkRenderSchedulerHostAdapter> ctocpp_;
};

} // namespace OHOS::ArkWeb

#endif // ARK_AAFWK_RENDER_SCHEDULER_HOST_ADAPTER_WRAPPER_H
