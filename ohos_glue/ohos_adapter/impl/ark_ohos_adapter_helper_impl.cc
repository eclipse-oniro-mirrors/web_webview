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

#include "ark_ohos_adapter_helper_impl.h"

#include "ark_aafwk_app_mgr_client_adapter_impl.h"
#include "ark_access_token_adapter_impl.h"
#include "ark_audio_capturer_adapter_impl.h"
#include "ark_audio_renderer_adapter_impl.h"
#include "ark_audio_system_manager_adapter_impl.h"
#include "ark_battery_info_impl.h"
#include "ark_battery_mgr_client_adapter_impl.h"
#include "ark_camera_manager_adapter_impl.h"
#include "ark_camera_surface_adapter_impl.h"
#include "ark_camera_surface_buffer_adapter_impl.h"
#include "ark_cert_manager_adapter_impl.h"
#include "ark_datashare_adapter_impl.h"
#include "ark_date_time_format_adapter_impl.h"
#include "ark_display_adapter_impl.h"
#include "ark_display_manager_adapter_impl.h"
#include "ark_enterprise_device_management_adapter_impl.h"
#include "ark_event_handler_adapter_impl.h"
#include "ark_hisysevent_adapter_impl.h"
#include "ark_hitrace_adapter_impl.h"
#include "ark_iconsumer_surface_adapter_impl.h"
#include "ark_imf_adapter_impl.h"
#include "ark_keystore_adapter_impl.h"
#include "ark_location_info_impl.h"
#include "ark_location_instance_impl.h"
#include "ark_location_proxy_adapter_impl.h"
#include "ark_location_request_config_impl.h"
#include "ark_media_codec_decoder_adapter_impl.h"
#include "ark_media_codec_encoder_adapter_impl.h"
#include "ark_mmi_adapter_impl.h"
#include "ark_native_image_adapter_impl.h"
#include "ark_net_connect_adapter_impl.h"
#include "ark_net_proxy_adapter_impl.h"
#include "ark_ohos_file_mapper_impl.h"
#include "ark_ohos_init_web_adapter_impl.h"
#include "ark_ohos_resource_adapter_impl.h"
#include "ark_ohos_web_data_base_adapter_impl.h"
#include "ark_paste_board_client_adapter_impl.h"
#include "ark_paste_data_adapter_impl.h"
#include "ark_paste_data_record_adapter_impl.h"
#include "ark_player_adapter_impl.h"
#include "ark_power_mgr_client_adapter_impl.h"
#include "ark_print_manager_adapter_impl.h"
#include "ark_running_lock_adapter_impl.h"
#include "ark_screen_capture_adapter_impl.h"
#include "ark_soc_perf_client_adapter_impl.h"
#include "ark_surface_buffer_adapter_impl.h"
#include "ark_system_properties_adapter_impl.h"
#include "ark_vsync_adapter_impl.h"
#include "ark_web_date_timezone_info_impl.h"
#include "ark_window_adapter_impl.h"

namespace OHOS::ArkWeb {

ArkWebRefPtr<ArkOhosAdapterHelper> ArkOhosAdapterHelper::GetInstance()
{
    static NWeb::OhosAdapterHelper& instance = NWeb::OhosAdapterHelper::GetInstance();
    static ArkOhosAdapterHelperImpl impl(instance);
    return &impl;
}

ArkOhosAdapterHelperImpl::ArkOhosAdapterHelperImpl(NWeb::OhosAdapterHelper& ref) : real_(ref) {}

ArkWebRefPtr<ArkAafwkAppMgrClientAdapter> ArkOhosAdapterHelperImpl::CreateAafwkAdapter()
{
    std::unique_ptr<NWeb::AafwkAppMgrClientAdapter> adapter = real_.CreateAafwkAdapter();
    std::shared_ptr<NWeb::AafwkAppMgrClientAdapter> shared = std::move(adapter);
    return new ArkAafwkAppMgrClientAdapterImpl(shared);
}

ArkWebRefPtr<ArkPowerMgrClientAdapter> ArkOhosAdapterHelperImpl::CreatePowerMgrClientAdapter()
{
    std::unique_ptr<NWeb::PowerMgrClientAdapter> adapter = real_.CreatePowerMgrClientAdapter();
    std::shared_ptr<NWeb::PowerMgrClientAdapter> shared = std::move(adapter);
    return new ArkPowerMgrClientAdapterImpl(shared);
}

ArkWebRefPtr<ArkDisplayManagerAdapter> ArkOhosAdapterHelperImpl::CreateDisplayMgrAdapter()
{
    std::unique_ptr<NWeb::DisplayManagerAdapter> adapter = real_.CreateDisplayMgrAdapter();
    std::shared_ptr<NWeb::DisplayManagerAdapter> shared = std::move(adapter);
    return new ArkDisplayManagerAdapterImpl(shared);
}

ArkWebRefPtr<ArkBatteryMgrClientAdapter> ArkOhosAdapterHelperImpl::CreateBatteryClientAdapter()
{
    std::unique_ptr<NWeb::BatteryMgrClientAdapter> adapter = real_.CreateBatteryClientAdapter();
    std::shared_ptr<NWeb::BatteryMgrClientAdapter> shared = std::move(adapter);
    return new ArkBatteryMgrClientAdapterImpl(shared);
}

ArkWebRefPtr<ArkNetConnectAdapter> ArkOhosAdapterHelperImpl::CreateNetConnectAdapter()
{
    std::unique_ptr<NWeb::NetConnectAdapter> adapter = real_.CreateNetConnectAdapter();
    std::shared_ptr<NWeb::NetConnectAdapter> shared = std::move(adapter);
    return new ArkNetConnectAdapterImpl(shared);
}

ArkWebRefPtr<ArkOhosWebDataBaseAdapter> ArkOhosAdapterHelperImpl::GetOhosWebDataBaseAdapterInstance()
{
    static NWeb::OhosWebDataBaseAdapter& instance = real_.GetOhosWebDataBaseAdapterInstance();
    static ArkOhosWebDataBaseAdapterImpl impl(instance);
    return &impl;
}

ArkWebRefPtr<ArkPasteBoardClientAdapter> ArkOhosAdapterHelperImpl::GetPasteBoard()
{
    static NWeb::PasteBoardClientAdapter& instance = real_.GetPasteBoard();
    static ArkPasteBoardClientAdapterImpl impl(instance);
    return &impl;
}

ArkWebRefPtr<ArkAudioRendererAdapter> ArkOhosAdapterHelperImpl::CreateAudioRendererAdapter()
{
    std::unique_ptr<NWeb::AudioRendererAdapter> adapter = real_.CreateAudioRendererAdapter();
    std::shared_ptr<NWeb::AudioRendererAdapter> shared = std::move(adapter);
    return new ArkAudioRendererAdapterImpl(shared);
}

ArkWebRefPtr<ArkAudioCapturerAdapter> ArkOhosAdapterHelperImpl::CreateAudioCapturerAdapter()
{
    std::unique_ptr<NWeb::AudioCapturerAdapter> adapter = real_.CreateAudioCapturerAdapter();
    std::shared_ptr<NWeb::AudioCapturerAdapter> shared = std::move(adapter);
    return new ArkAudioCapturerAdapterImpl(shared);
}

ArkWebRefPtr<ArkAudioSystemManagerAdapter> ArkOhosAdapterHelperImpl::GetAudioSystemManager()
{
    static NWeb::AudioSystemManagerAdapter& instance = real_.GetAudioSystemManager();
    static ArkAudioSystemManagerAdapterImpl impl(instance);
    return &impl;
}

ArkWebRefPtr<ArkOhosWebPermissionDataBaseAdapter> ArkOhosAdapterHelperImpl::GetWebPermissionDataBaseInstance()
{
    static NWeb::OhosWebPermissionDataBaseAdapter& instance = real_.GetWebPermissionDataBaseInstance();
    static ArkOhosWebPermissionDataBaseAdapterImpl impl(instance);
    return &impl;
}

ArkWebRefPtr<ArkMMIAdapter> ArkOhosAdapterHelperImpl::CreateMMIAdapter()
{
    std::unique_ptr<NWeb::MMIAdapter> adapter = real_.CreateMMIAdapter();
    std::shared_ptr<NWeb::MMIAdapter> shared = std::move(adapter);
    return new ArkMMIAdapterImpl(shared);
}

ArkWebRefPtr<ArkSocPerfClientAdapter> ArkOhosAdapterHelperImpl::CreateSocPerfClientAdapter()
{
    std::unique_ptr<NWeb::SocPerfClientAdapter> adapter = real_.CreateSocPerfClientAdapter();
    std::shared_ptr<NWeb::SocPerfClientAdapter> shared = std::move(adapter);
    return new ArkSocPerfClientAdapterImpl(shared);
}

ArkWebRefPtr<ArkOhosResourceAdapter> ArkOhosAdapterHelperImpl::GetResourceAdapter(const ArkWebString& hapPath)
{
    std::unique_ptr<NWeb::OhosResourceAdapter> adapter = real_.GetResourceAdapter(ArkWebStringStructToClass(hapPath));
    std::shared_ptr<NWeb::OhosResourceAdapter> shared = std::move(adapter);
    return new ArkOhosResourceAdapterImpl(shared);
}

ArkWebRefPtr<ArkSystemPropertiesAdapter> ArkOhosAdapterHelperImpl::GetSystemPropertiesInstance()
{
    static NWeb::SystemPropertiesAdapter& instance = real_.GetSystemPropertiesInstance();
    static ArkSystemPropertiesAdapterImpl impl(instance);
    return &impl;
}

ArkWebRefPtr<ArkVSyncAdapter> ArkOhosAdapterHelperImpl::GetVSyncAdapter()
{
    static NWeb::VSyncAdapter& instance = real_.GetVSyncAdapter();
    static ArkVSyncAdapterImpl impl(instance);
    return &impl;
}

ArkWebRefPtr<ArkOhosInitWebAdapter> ArkOhosAdapterHelperImpl::GetInitWebAdapter()
{
    std::unique_ptr<NWeb::OhosInitWebAdapter> adapter = real_.GetInitWebAdapter();
    std::shared_ptr<NWeb::OhosInitWebAdapter> shared = std::move(adapter);
    return new ArkOhosInitWebAdapterImpl(shared);
}

ArkWebRefPtr<ArkKeystoreAdapter> ArkOhosAdapterHelperImpl::GetKeystoreAdapterInstance()
{
    static NWeb::KeystoreAdapter& instance = real_.GetKeystoreAdapterInstance();
    static ArkKeystoreAdapterImpl impl(instance);
    return &impl;
}

ArkWebRefPtr<ArkEnterpriseDeviceManagementAdapter> ArkOhosAdapterHelperImpl::GetEnterpriseDeviceManagementInstance()
{
    static NWeb::EnterpriseDeviceManagementAdapter& instance = real_.GetEnterpriseDeviceManagementInstance();
    static ArkEnterpriseDeviceManagementAdapterImpl impl(instance);
    return &impl;
}

ArkWebRefPtr<ArkDatashareAdapter> ArkOhosAdapterHelperImpl::GetDatashareInstance()
{
    static NWeb::DatashareAdapter& instance = real_.GetDatashareInstance();
    static ArkDatashareAdapterImpl impl(instance);
    return &impl;
}

ArkWebRefPtr<ArkIMFAdapter> ArkOhosAdapterHelperImpl::CreateIMFAdapter()
{
    std::unique_ptr<NWeb::IMFAdapter> adapter = real_.CreateIMFAdapter();
    std::shared_ptr<NWeb::IMFAdapter> shared = std::move(adapter);
    return new ArkIMFAdapterImpl(shared);
}

ArkWebRefPtr<ArkCertManagerAdapter> ArkOhosAdapterHelperImpl::GetRootCertDataAdapter()
{
    std::unique_ptr<NWeb::CertManagerAdapter> adapter = real_.GetRootCertDataAdapter();
    std::shared_ptr<NWeb::CertManagerAdapter> shared = std::move(adapter);
    return new ArkCertManagerAdapterImpl(shared);
}

ArkWebRefPtr<ArkAccessTokenAdapter> ArkOhosAdapterHelperImpl::GetAccessTokenAdapterInstance()
{
    static NWeb::AccessTokenAdapter& instance = real_.GetAccessTokenAdapterInstance();
    static ArkAccessTokenAdapterImpl impl(instance);
    return &impl;
}

ArkWebRefPtr<ArkEventHandlerAdapter> ArkOhosAdapterHelperImpl::GetEventHandlerAdapter()
{
    std::unique_ptr<NWeb::EventHandlerAdapter> adapter = real_.GetEventHandlerAdapter();
    std::shared_ptr<NWeb::EventHandlerAdapter> shared = std::move(adapter);
    return new ArkEventHandlerAdapterImpl(shared);
}

ArkWebRefPtr<ArkPrintManagerAdapter> ArkOhosAdapterHelperImpl::GetPrintManagerInstance()
{
    static NWeb::PrintManagerAdapter& instance = real_.GetPrintManagerInstance();
    static ArkPrintManagerAdapterImpl impl(instance);
    return &impl;
}

ArkWebRefPtr<ArkIConsumerSurfaceAdapter> ArkOhosAdapterHelperImpl::CreateConsumerSurfaceAdapter()
{
    std::unique_ptr<NWeb::IConsumerSurfaceAdapter> adapter = real_.CreateConsumerSurfaceAdapter();
    std::shared_ptr<NWeb::IConsumerSurfaceAdapter> shared = std::move(adapter);
    return new ArkIConsumerSurfaceAdapterImpl(shared);
}

ArkWebRefPtr<ArkPlayerAdapter> ArkOhosAdapterHelperImpl::CreatePlayerAdapter()
{
    std::unique_ptr<NWeb::PlayerAdapter> adapter = real_.CreatePlayerAdapter();
    std::shared_ptr<NWeb::PlayerAdapter> shared = std::move(adapter);
    return new ArkPlayerAdapterImpl(shared);
}

ArkWebRefPtr<ArkWindowAdapter> ArkOhosAdapterHelperImpl::GetWindowAdapterInstance()
{
    static NWeb::WindowAdapter& instance = real_.GetWindowAdapterInstance();
    static ArkWindowAdapterImpl impl(instance);
    return &impl;
}

ArkWebRefPtr<ArkHiSysEventAdapter> ArkOhosAdapterHelperImpl::GetHiSysEventAdapterInstance()
{
    static NWeb::HiSysEventAdapter& instance = real_.GetHiSysEventAdapterInstance();
    static ArkHiSysEventAdapterImpl impl(instance);
    return &impl;
}

ArkWebRefPtr<ArkHiTraceAdapter> ArkOhosAdapterHelperImpl::GetHiTraceAdapterInstance()
{
    static NWeb::HiTraceAdapter& instance = real_.GetHiTraceAdapterInstance();
    static ArkHiTraceAdapterImpl impl(instance);
    return &impl;
}

ArkWebRefPtr<ArkNetProxyAdapter> ArkOhosAdapterHelperImpl::GetNetProxyInstance()
{
    static NWeb::NetProxyAdapter& instance = real_.GetNetProxyInstance();
    static ArkNetProxyAdapterImpl impl(instance);
    return &impl;
}

ArkWebRefPtr<ArkCameraManagerAdapter> ArkOhosAdapterHelperImpl::GetCameraManagerAdapter()
{
    static NWeb::CameraManagerAdapter& instance = real_.GetCameraManagerAdapter();
    static ArkCameraManagerAdapterImpl impl(instance);
    return &impl;
}

ArkWebRefPtr<ArkScreenCaptureAdapter> ArkOhosAdapterHelperImpl::CreateScreenCaptureAdapter()
{
    std::unique_ptr<NWeb::ScreenCaptureAdapter> adapter = real_.CreateScreenCaptureAdapter();
    std::shared_ptr<NWeb::ScreenCaptureAdapter> shared = std::move(adapter);
    return new ArkScreenCaptureAdapterImpl(shared);
}

ArkWebRefPtr<ArkDateTimeFormatAdapter> ArkOhosAdapterHelperImpl::CreateDateTimeFormatAdapter()
{
    std::unique_ptr<NWeb::DateTimeFormatAdapter> adapter = real_.CreateDateTimeFormatAdapter();
    std::shared_ptr<NWeb::DateTimeFormatAdapter> shared = std::move(adapter);
    return new ArkDateTimeFormatAdapterImpl(shared);
}

ArkWebRefPtr<ArkMediaCodecDecoderAdapter> ArkOhosAdapterHelperImpl::CreateMediaCodecDecoderAdapter()
{
    std::unique_ptr<NWeb::MediaCodecDecoderAdapter> adapter = real_.CreateMediaCodecDecoderAdapter();
    std::shared_ptr<NWeb::MediaCodecDecoderAdapter> shared = std::move(adapter);
    return new ArkMediaCodecDecoderAdapterImpl(shared);
}

ArkWebRefPtr<ArkNativeImageAdapter> ArkOhosAdapterHelperImpl::CreateNativeImageAdapter()
{
    std::unique_ptr<NWeb::NativeImageAdapter> adapter = real_.CreateNativeImageAdapter();
    std::shared_ptr<NWeb::NativeImageAdapter> shared = std::move(adapter);
    return new ArkNativeImageAdapterImpl(shared);
}

ArkWebRefPtr<ArkMediaCodecListAdapter> ArkOhosAdapterHelperImpl::GetMediaCodecListAdapter()
{
    static NWeb::MediaCodecListAdapter& instance = real_.GetMediaCodecListAdapter();
    static ArkMediaCodecListAdapterImpl impl(instance);
    return &impl;
}

ArkWebRefPtr<ArkMediaCodecAdapter> ArkOhosAdapterHelperImpl::CreateMediaCodecEncoderAdapter()
{
    std::unique_ptr<NWeb::MediaCodecAdapter> adapter = real_.CreateMediaCodecEncoderAdapter();
    std::shared_ptr<NWeb::MediaCodecAdapter> shared = std::move(adapter);
    return new ArkMediaCodecEncoderAdapterImpl(shared);
}
} // namespace OHOS::ArkWeb
