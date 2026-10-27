/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef ANI_REMOVE_VISITED_LINKS_CALLBACK_H
#define ANI_REMOVE_VISITED_LINKS_CALLBACK_H

#include <ani.h>

#include "nweb_log.h"

#include "nweb_remove_visited_links_callback.h"

namespace OHOS {
namespace NWeb {

class AniRemoveVisitedLinksCallback : public NWebRemoveVisitedLinksCallback {
public:
    AniRemoveVisitedLinksCallback(ani_env* env, ani_resolver resolver)
        : env_(env), resolver_(resolver) {}
    ~AniRemoveVisitedLinksCallback() = default;

    void OnRemoveComplete() override;

private:
    ani_env* env_ = nullptr;
    ani_resolver resolver_ = nullptr;
};

} // namespace NWeb
} // namespace OHOS

#endif // ANI_REMOVE_VISITED_LINKS_CALLBACK_H
