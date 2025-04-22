/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <ani.h>
#include <array>
#include <cstdlib>
#include <ctime>
#include <iostream>

#include "ani_webview_controller.h"
#include "ani_proxy_config.h"
#include "nweb_log.h"

namespace OHOS {
namespace NWeb {

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    WVLOG_I("Webview ANI_Constructor");
    ani_env *env = nullptr;
    ani_status status = vm->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK || !env) {
        WVLOG_E("ANI_Constructor GetEnv status: %{public}d", status);
        return ANI_NOT_FOUND;
    }

    StsWebviewControllerInit(env);
    StsBackForwardListInit(env);
    StsWebSchemeHandlerResponseInit(env);
    StsWebDownloadDelegateInit(env);
    StsWebCookieManagerInit(env);
    StsWebProxyConfigInit(env);
    StsCleanerInit(env);
    *result = ANI_VERSION_1;
    return ANI_OK;
}
}

} // namespace NWeb
} // namespace OHOS