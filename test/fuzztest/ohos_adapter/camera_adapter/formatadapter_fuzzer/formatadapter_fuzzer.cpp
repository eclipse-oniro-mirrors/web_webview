/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "formatadapter_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>

#define FORMAT_ADAPTER_IMPL
#define private public
#include "camera_manager_adapter_impl.h"
#include "format_adapter_impl.cpp"
#include "format_adapter_impl.h"
#include "nweb_surface_adapter.h"

using namespace OHOS::NWeb;

namespace OHOS {
constexpr int MAX_SET_NUMBER = 1000;

bool FormatAdapterFuzzTest(const uint8_t* data, size_t size)
{
    OHOS::NWeb::FormatAdapterImpl adapter;
    FuzzedDataProvider dataProvider(data, size);
    uint32_t randomNum = dataProvider.ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    adapter.SetWidth(randomNum);
    adapter.SetHeight(randomNum);
    adapter.SetFrameRate(randomNum);
    adapter.SetPixelFormat(VideoPixelFormatAdapter::FORMAT_UNKNOWN);

    adapter.GetWidth();
    adapter.GetHeight();
    adapter.GetFrameRate();
    adapter.GetPixelFormat();
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FormatAdapterFuzzTest(data, size);
    return 0;
}
