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

#include "displaydestroy_fuzzer.h"

#include <cstring>
#include <securec.h>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#include "display_manager_adapter_impl.h"
#undef private
#include "display_info.h"

using namespace OHOS::NWeb;
using namespace OHOS::Rosen;

namespace OHOS {
class DisplayListenerAdapterFuzzTest : public DisplayListenerAdapter {
public:
DisplayListenerAdapterFuzzTest() = default;

    virtual ~DisplayListenerAdapterFuzzTest() = default;

    void OnCreate(DisplayId) override {}
    void OnDestroy(DisplayId) override {}
    void OnChange(DisplayId) override {}
};
constexpr int MAX_SET_NUMBER = 1000;

bool DisplayDestroyFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    FuzzedDataProvider dataProvider(data, size);
    std::shared_ptr<DisplayListenerAdapter> listener = nullptr;
    DisplayListenerAdapterImpl display(listener);
    DisplayId displayId = dataProvider.ConsumeIntegralInRange<DisplayId>(0, MAX_SET_NUMBER);
    display.OnCreate(displayId);
    display.OnDestroy(displayId);
    display.OnChange(displayId);
    display.CheckOnlyRefreshRateDecreased(displayId);
    std::shared_ptr<DisplayListenerAdapter> listener1
        = std::make_shared<DisplayListenerAdapterFuzzTest>();
    DisplayListenerAdapterImpl display1(listener1);
    display1.OnCreate(displayId);
    display1.OnDestroy(displayId);
    display1.OnChange(displayId);
    displayId = DisplayManager::GetInstance().GetDefaultDisplayId();
    display1.OnChange(displayId);
    auto displayPtr = DisplayManager::GetInstance().GetDefaultDisplay();
    if (displayPtr == nullptr) {
        return false;
    }
    auto displayInfo = displayPtr->GetDisplayInfo();
    if (displayInfo == nullptr) {
        return false;
    }
    display1.ConvertDisplayInfo(*displayInfo);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DisplayDestroyFuzzTest(data, size);
    return 0;
}
