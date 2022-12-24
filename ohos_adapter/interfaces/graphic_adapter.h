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

#ifndef GRAPHIC_ADAPTER_H
#define GRAPHIC_ADAPTER_H

#include <functional>

namespace OHOS::NWeb {
enum class VSyncErrorCode {
    SUCCESS,
    ERROR,
};

class VSyncAdapter {
public:
    VSyncAdapter() = default;

    virtual ~VSyncAdapter() = default;

    virtual VSyncErrorCode RequestVsync(void* data, std::function<void(int64_t, void*)> NWebVSyncCb) = 0;
};
} // namespace OHOS::NWeb

#endif // GRAPHIC_ADAPTER_H