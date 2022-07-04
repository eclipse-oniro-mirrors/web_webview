/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <unistd.h>

#include "hilog/log.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_web_data_base.h"
#include "napi_web_storage.h"

namespace OHOS {
EXTERN_C_START
static napi_value WebViewExport(napi_env env, napi_value exports)
{
    NapiWebDataBase::Init(env, exports);
    NapiWebStorage::Init(env, exports);
    return exports;
}
EXTERN_C_END

/*
 * Module register function
 */
NAPI_MODULE(web, WebViewExport)
} // namesapce OHOS
