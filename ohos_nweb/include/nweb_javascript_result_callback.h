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

#ifndef NWEB_JAVASCRIPT_RESULT_CALLBACK_H
#define NWEB_JAVASCRIPT_RESULT_CALLBACK_H

#include <string>
#include <vector>
#include "nweb_export.h"
#include "nweb_value.h"

namespace OHOS::NWeb {
class OHOS_NWEB_EXPORT NWebJavaScriptResultCallBack {
public:
    NWebJavaScriptResultCallBack() = default;

    virtual ~NWebJavaScriptResultCallBack() = default;

    virtual std::shared_ptr<NWebValue> GetJavaScriptResult(std::vector<std::shared_ptr<NWebValue>> args,
        const std::string& method, const std::string& object_name, int32_t routing_id, int32_t object_id) = 0;

    virtual bool HasJavaScriptObjectMethods(int32_t object_id, const std::string& method_name) = 0;

    virtual std::shared_ptr<NWebValue> GetJavaScriptObjectMethods(int32_t object_id) = 0;

    virtual void RemoveJavaScriptObjectHolder(int32_t holder, int32_t objectId) = 0;
    virtual void RemoveTransientJavaScriptObject() = 0;
};
} // namespace OHOS::NWeb

#endif // NWEB_JAVASCRIPT_RESULT_CALLBACK_H
