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

#include <cstring>
#include <securec.h>

#include <fuzzer/FuzzedDataProvider.h>

#include "nweb_snapshot_data_base.h"

using namespace OHOS::NWeb;

namespace OHOS {
namespace NWeb {
constexpr uint8_t MAX_STRING_LENGTH = 255;

bool NWebSnapshotDataBaseFuzzTest_001(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return false;
    }

    FuzzedDataProvider dataProvider(data, size);
    std::string url = dataProvider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    NWebSnapshotDataBase::Instance().GetSnapshotDataItem(url);
    return true;
}
} // namespace NWeb
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::NWeb::NWebSnapshotDataBaseFuzzTest_001(data, size);
    return 0;
}
