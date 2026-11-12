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

#include "ohos_nweb/ctocpp/ark_web_color_suggestion_vector_ctocpp.h"

#include "base/include/ark_web_types.h"

namespace OHOS::ArkWeb {

std::vector<OHOS::NWeb::NWebColorSuggestion> ArkWebColorSuggestionVectorStructToClass(
    const ArkWebColorSuggestionVector& struct_value)
{
    std::vector<OHOS::NWeb::NWebColorSuggestion> class_value;
    if (struct_value.size > 0 && struct_value.value != nullptr) {
        for (int count = 0; count < struct_value.size; count++) {
            if (struct_value.value[count] == nullptr) {
                continue;
            }
            OHOS::NWeb::NWebColorSuggestion nweb_suggestion;
            nweb_suggestion.color = ArkWebStringStructToClass(struct_value.value[count]->color);
            nweb_suggestion.label = ArkWebStringStructToClass(struct_value.value[count]->label);
            class_value.push_back(nweb_suggestion);
        }
    }

    return class_value;
}

} // namespace OHOS::ArkWeb
