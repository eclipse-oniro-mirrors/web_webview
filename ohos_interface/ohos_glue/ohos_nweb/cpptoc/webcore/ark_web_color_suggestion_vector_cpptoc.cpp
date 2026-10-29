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

#include "ohos_nweb/cpptoc/ark_web_color_suggestion_vector_cpptoc.h"

#include "base/include/ark_web_macros.h"
#include "base/include/ark_web_types.h"
#include "base/include/ark_web_memory.h"

namespace OHOS::ArkWeb {

ArkWebColorSuggestionVector ArkWebColorSuggestionVectorClassToStruct(
    const std::vector<OHOS::NWeb::NWebColorSuggestion>& class_value)
{
    ArkWebColorSuggestionVector struct_value = { .size = static_cast<int>(class_value.size()),
        .ark_web_mem_free_func = ArkWebMemFree };
    if (struct_value.size > 0) {
        struct_value.value = (ark_web_color_suggestion_t**)ArkWebMemMalloc(
            sizeof(ark_web_color_suggestion_t*) * struct_value.size);
        if (struct_value.value == nullptr) {
            struct_value.size = 0;
            return struct_value;
        }
        for (int i = 0; i < struct_value.size; i++) {
            struct_value.value[i] = nullptr;
        }

        int count = 0;
        for (auto it = class_value.begin(); it != class_value.end(); it++) {
            struct_value.value[count] = new ark_web_color_suggestion_t();
            struct_value.value[count]->color = ArkWebStringClassToStruct(it->color);
            struct_value.value[count]->label = ArkWebStringClassToStruct(it->label);
            count++;
        }
    }

    return struct_value;
}

void ArkWebColorSuggestionVectorStructRelease(ArkWebColorSuggestionVector& struct_value)
{
    if (struct_value.size > 0 && struct_value.value != nullptr) {
        for (int i = 0; i < struct_value.size; i++) {
            if (struct_value.value[i] != nullptr) {
                ArkWebStringStructRelease(struct_value.value[i]->color);
                ArkWebStringStructRelease(struct_value.value[i]->label);
                delete struct_value.value[i];
                struct_value.value[i] = nullptr;
            }
        }
    }
    struct_value.size = 0;
    SAFE_FREE(struct_value.value, struct_value.ark_web_mem_free_func);
}

} // namespace OHOS::ArkWeb
