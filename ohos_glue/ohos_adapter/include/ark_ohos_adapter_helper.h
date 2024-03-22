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

#ifndef ARK_OHOS_ADAPTER_HELPER_H
#define ARK_OHOS_ADAPTER_HELPER_H

#include "include/ark_aafwk_app_mgr_client_adapter.h"
#include "include/ark_access_token_adapter.h"
#include "include/ark_audio_capturer_adapter.h"
#include "include/ark_audio_renderer_adapter.h"
#include "include/ark_audio_system_manager_adapter.h"
#include "include/ark_battery_mgr_client_adapter.h"
#include "include/ark_camera_manager_adapter.h"
#include "include/ark_cert_manager_adapter.h"
#include "include/ark_datashare_adapter.h"
#include "include/ark_date_time_format_adapter.h"
#include "include/ark_display_manager_adapter.h"
#include "include/ark_enterprise_device_management_adapter.h"
#include "include/ark_event_handler_adapter.h"
#include "include/ark_flowbuffer_adapter.h"
#include "include/ark_graphic_adapter.h"
#include "include/ark_hisysevent_adapter.h"
#include "include/ark_hitrace_adapter.h"
#include "include/ark_imf_adapter.h"
#include "include/ark_keystore_adapter.h"
#include "include/ark_media_adapter.h"
#include "include/ark_media_codec_decoder_adapter.h"
#include "include/ark_media_codec_encoder_adapter.h"
#include "include/ark_mmi_adapter.h"
#include "include/ark_net_connect_adapter.h"
#include "include/ark_net_proxy_adapter.h"
#include "include/ark_ohos_init_web_adapter.h"
#include "include/ark_ohos_resource_adapter.h"
#include "include/ark_ohos_web_data_base_adapter.h"
#include "include/ark_pasteboard_client_adapter.h"
#include "include/ark_power_mgr_client_adapter.h"
#include "include/ark_print_manager_adapter.h"
#include "include/ark_screen_capture_adapter.h"
#include "include/ark_soc_perf_client_adapter.h"
#include "include/ark_system_properties_adapter.h"
#include "include/ark_web_base_ref_counted.h"
#include "include/ark_web_types.h"

namespace OHOS::ArkWeb {

/*--web engine(source=library)--*/
class ArkOhosAdapterHelper : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    static ArkWebRefPtr<ArkOhosAdapterHelper> GetInstance();

    virtual ~ArkOhosAdapterHelper() = default;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkAafwkAppMgrClientAdapter> CreateAafwkAdapter() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkPowerMgrClientAdapter> CreatePowerMgrClientAdapter() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkDisplayManagerAdapter> CreateDisplayMgrAdapter() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkBatteryMgrClientAdapter> CreateBatteryClientAdapter() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkNetConnectAdapter> CreateNetConnectAdapter() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkOhosWebDataBaseAdapter> GetOhosWebDataBaseAdapterInstance() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkPasteBoardClientAdapter> GetPasteBoard() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkAudioRendererAdapter> CreateAudioRendererAdapter() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkAudioCapturerAdapter> CreateAudioCapturerAdapter() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkAudioSystemManagerAdapter> GetAudioSystemManager() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkOhosWebPermissionDataBaseAdapter> GetWebPermissionDataBaseInstance() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkMMIAdapter> CreateMMIAdapter() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkSocPerfClientAdapter> CreateSocPerfClientAdapter() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkOhosResourceAdapter> GetResourceAdapter(const ArkWebString& hapPath) = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkSystemPropertiesAdapter> GetSystemPropertiesInstance() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkVSyncAdapter> GetVSyncAdapter() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkOhosInitWebAdapter> GetInitWebAdapter() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkKeystoreAdapter> GetKeystoreAdapterInstance() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkEnterpriseDeviceManagementAdapter> GetEnterpriseDeviceManagementInstance() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkDatashareAdapter> GetDatashareInstance() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkIMFAdapter> CreateIMFAdapter() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkCertManagerAdapter> GetRootCertDataAdapter() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkAccessTokenAdapter> GetAccessTokenAdapterInstance() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkEventHandlerAdapter> GetEventHandlerAdapter() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkPrintManagerAdapter> GetPrintManagerInstance() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkIConsumerSurfaceAdapter> CreateConsumerSurfaceAdapter() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkPlayerAdapter> CreatePlayerAdapter() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkWindowAdapter> GetWindowAdapterInstance() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkHiSysEventAdapter> GetHiSysEventAdapterInstance() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkHiTraceAdapter> GetHiTraceAdapterInstance() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkNetProxyAdapter> GetNetProxyInstance() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkCameraManagerAdapter> GetCameraManagerAdapter() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkScreenCaptureAdapter> CreateScreenCaptureAdapter() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkDateTimeFormatAdapter> CreateDateTimeFormatAdapter() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkMediaCodecDecoderAdapter> CreateMediaCodecDecoderAdapter() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkNativeImageAdapter> CreateNativeImageAdapter() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkMediaCodecAdapter> CreateMediaCodecEncoderAdapter() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkMediaCodecListAdapter> GetMediaCodecListAdapter() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkFlowbufferAdapter> CreateFlowbufferAdapter() = 0;
};
} // namespace OHOS::ArkWeb

#endif // ARK_OHOS_ADAPTER_HELPER_H
