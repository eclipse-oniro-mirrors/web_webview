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

#include "audiogetsampling_fuzzer.h"

#include <cstring>
#include <securec.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "audio_renderer_adapter_impl.h"

using namespace OHOS::NWeb;

namespace OHOS {
constexpr uint32_t MAX_STRING_LENGTH = 10000;
bool AudioGetSamplingFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    FuzzedDataProvider fuzzedData(data, size);
    AudioRendererAdapterImpl adapter;
    uint32_t samplingRateValue = fuzzedData.ConsumeIntegralInRange<uint32_t>(0, MAX_STRING_LENGTH);
    AudioAdapterSamplingRate samplingRate = static_cast<AudioAdapterSamplingRate>(samplingRateValue);
    adapter.GetAudioSamplingRate(samplingRate);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AudioGetSamplingFuzzTest(data, size);
    return 0;
}
