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

#include "ohosadapterhelper_fuzzer.h"

#include <securec.h>
#include <sys/mman.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "media_errors.h"
#include "ohos_adapter_helper.h"

using namespace OHOS::NWeb;
const std::string DEFAULT_MOUSE_DRAG_IMAGE { "/system/etc/device_status/drag_icon/Copy_Drag.svg" };

namespace OHOS {

bool OhosAdapterHelperFuzzTest(const uint8_t* data, size_t size)
{
    auto decoderAdapter = OhosAdapterHelper::GetInstance().CreateOhosImageDecoderAdapter();
    auto mgrAdapter = OhosAdapterHelper::GetInstance().CreatePowerMgrClientAdapter();
    auto batteryClientAdapter = OhosAdapterHelper::GetInstance().CreateBatteryClientAdapter();
    auto displayMgrAdapter = OhosAdapterHelper::GetInstance().CreateDisplayMgrAdapter();
    auto netConnectAdapter = OhosAdapterHelper::GetInstance().CreateNetConnectAdapter();
    auto audioRendererAdapter = OhosAdapterHelper::GetInstance().CreateAudioRendererAdapter();
    auto audioCapturerAdapter = OhosAdapterHelper::GetInstance().CreateAudioCapturerAdapter();
    auto initWebAdapter = OhosAdapterHelper::GetInstance().GetInitWebAdapter();
    auto iMFAdapter = OhosAdapterHelper::GetInstance().CreateIMFAdapter();
    auto rootCertDataAdapter = OhosAdapterHelper::GetInstance().GetRootCertDataAdapter();
    auto eventHandlerAdapter = OhosAdapterHelper::GetInstance().GetEventHandlerAdapter();
    auto playerAdapter = OhosAdapterHelper::GetInstance().CreatePlayerAdapter();
    auto screenCaptureAdapter = OhosAdapterHelper::GetInstance().CreateScreenCaptureAdapter();
    auto dateTimeFormatAdapter = OhosAdapterHelper::GetInstance().CreateDateTimeFormatAdapter();
    auto mediaCodecDecoderAdapter = OhosAdapterHelper::GetInstance().CreateMediaCodecDecoderAdapter();
    auto nativeImageAdapter = OhosAdapterHelper::GetInstance().CreateNativeImageAdapter();
    auto mediaAVSessionAdapter = OhosAdapterHelper::GetInstance().CreateMediaAVSessionAdapter();
    auto sensorAdapter = OhosAdapterHelper::GetInstance().CreateSensorAdapter();
    auto audioCodecDecoderAdapter = OhosAdapterHelper::GetInstance().CreateAudioCodecDecoderAdapter();
    auto drmAdapter = OhosAdapterHelper::GetInstance().CreateDrmAdapter();

    return true;
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::OhosAdapterHelperFuzzTest(data, size);
    return 0;
}
