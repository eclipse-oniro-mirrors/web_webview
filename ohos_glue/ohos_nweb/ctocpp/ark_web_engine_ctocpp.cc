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

#include "ohos_nweb/ctocpp/ark_web_engine_ctocpp.h"
#include "base/ctocpp/ark_web_ctocpp_macros.h"
#include "ohos_nweb/bridge/ark_web_nweb_bridge_helper.h"
#include "ohos_nweb/cpptoc/ark_web_engine_init_args_cpptoc.h"
#include "ohos_nweb/cpptoc/ark_web_nweb_create_info_cpptoc.h"
#include "ohos_nweb/ctocpp/ark_web_cookie_manager_ctocpp.h"
#include "ohos_nweb/ctocpp/ark_web_data_base_ctocpp.h"
#include "ohos_nweb/ctocpp/ark_web_download_manager_ctocpp.h"
#include "ohos_nweb/ctocpp/ark_web_nweb_ctocpp.h"
#include "ohos_nweb/ctocpp/ark_web_web_storage_ctocpp.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
ArkWebRefPtr<ArkWebEngine> ArkWebEngine::GetInstance() {
  ARK_WEB_CTOCPP_DV_LOG();

  using ArkWebEngineGetInstanceFunc = ark_web_engine_t *(*)();
  ArkWebEngineGetInstanceFunc ark_web_engine_get_instance =
      reinterpret_cast<ArkWebEngineGetInstanceFunc>(
          ArkWebNWebBridgeHelper::GetInstance().LoadFuncSymbol(
              "ark_web_engine_get_instance_static"));
  if (!ark_web_engine_get_instance) {
    ARK_WEB_CTOCPP_WRAN_LOG("failed to get static function symbol");
    return nullptr;
  }

  // Execute
  ark_web_engine_t *_retval = ark_web_engine_get_instance();

  // Return type: refptr_same
  return ArkWebEngineCToCpp::Invert(_retval);
}

ARK_WEB_NO_SANITIZE
ArkWebRefPtr<ArkWebNWeb>
ArkWebEngineCToCpp::CreateNWeb(ArkWebRefPtr<ArkWebNWebCreateInfo> create_info) {
  ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

  ark_web_engine_t *_struct = GetStruct();
  ARK_WEB_CTOCPP_CHECK_PARAM(_struct, nullptr);

  ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, create_nweb, nullptr);

  // Execute
  ark_web_nweb_t *_retval = _struct->create_nweb(
      _struct, ArkWebNWebCreateInfoCppToC::Invert(create_info));

  // Return type: refptr_same
  return ArkWebNWebCToCpp::Invert(_retval);
}

ARK_WEB_NO_SANITIZE
ArkWebRefPtr<ArkWebNWeb> ArkWebEngineCToCpp::GetNWeb(int32_t nweb_id) {
  ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

  ark_web_engine_t *_struct = GetStruct();
  ARK_WEB_CTOCPP_CHECK_PARAM(_struct, nullptr);

  ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_nweb, nullptr);

  // Execute
  ark_web_nweb_t *_retval = _struct->get_nweb(_struct, nweb_id);

  // Return type: refptr_same
  return ArkWebNWebCToCpp::Invert(_retval);
}

ARK_WEB_NO_SANITIZE
ArkWebRefPtr<ArkWebDataBase> ArkWebEngineCToCpp::GetDataBase() {
  ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

  ark_web_engine_t *_struct = GetStruct();
  ARK_WEB_CTOCPP_CHECK_PARAM(_struct, nullptr);

  ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_data_base, nullptr);

  // Execute
  ark_web_data_base_t *_retval = _struct->get_data_base(_struct);

  // Return type: refptr_same
  return ArkWebDataBaseCToCpp::Invert(_retval);
}

ARK_WEB_NO_SANITIZE
ArkWebRefPtr<ArkWebWebStorage> ArkWebEngineCToCpp::GetWebStorage() {
  ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

  ark_web_engine_t *_struct = GetStruct();
  ARK_WEB_CTOCPP_CHECK_PARAM(_struct, nullptr);

  ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_web_storage, nullptr);

  // Execute
  ark_web_web_storage_t *_retval = _struct->get_web_storage(_struct);

  // Return type: refptr_same
  return ArkWebWebStorageCToCpp::Invert(_retval);
}

ARK_WEB_NO_SANITIZE
ArkWebRefPtr<ArkWebCookieManager> ArkWebEngineCToCpp::GetCookieManager() {
  ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

  ark_web_engine_t *_struct = GetStruct();
  ARK_WEB_CTOCPP_CHECK_PARAM(_struct, nullptr);

  ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_cookie_manager, nullptr);

  // Execute
  ark_web_cookie_manager_t *_retval = _struct->get_cookie_manager(_struct);

  // Return type: refptr_same
  return ArkWebCookieManagerCToCpp::Invert(_retval);
}

ARK_WEB_NO_SANITIZE
ArkWebRefPtr<ArkWebDownloadManager> ArkWebEngineCToCpp::GetDownloadManager() {
  ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

  ark_web_engine_t *_struct = GetStruct();
  ARK_WEB_CTOCPP_CHECK_PARAM(_struct, nullptr);

  ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_download_manager, nullptr);

  // Execute
  ark_web_download_manager_t *_retval = _struct->get_download_manager(_struct);

  // Return type: refptr_same
  return ArkWebDownloadManagerCToCpp::Invert(_retval);
}

ARK_WEB_NO_SANITIZE
void ArkWebEngineCToCpp::SetWebTag(int32_t nweb_id, const char *web_tag) {
  ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

  ark_web_engine_t *_struct = GetStruct();
  ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

  ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_web_tag, );

  // Execute
  _struct->set_web_tag(_struct, nweb_id, web_tag);
}

ARK_WEB_NO_SANITIZE
void ArkWebEngineCToCpp::InitializeWebEngine(
    ArkWebRefPtr<ArkWebEngineInitArgs> init_args) {
  ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

  ark_web_engine_t *_struct = GetStruct();
  ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

  ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, initialize_web_engine, );

  // Execute
  _struct->initialize_web_engine(_struct,
                                 ArkWebEngineInitArgsCppToC::Invert(init_args));
}

ARK_WEB_NO_SANITIZE
void ArkWebEngineCToCpp::PrepareForPageLoad(const ArkWebString &url,
                                            bool preconnectable,
                                            int32_t num_sockets) {
  ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

  ark_web_engine_t *_struct = GetStruct();
  ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

  ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, prepare_for_page_load, );

  // Execute
  _struct->prepare_for_page_load(_struct, &url, preconnectable, num_sockets);
}

ARK_WEB_NO_SANITIZE
void ArkWebEngineCToCpp::SetWebDebuggingAccess(bool isEnableDebug) {
  ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

  ark_web_engine_t *_struct = GetStruct();
  ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

  ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_web_debugging_access, );

  // Execute
  _struct->set_web_debugging_access(_struct, isEnableDebug);
}

ArkWebEngineCToCpp::ArkWebEngineCToCpp() {
}

ArkWebEngineCToCpp::~ArkWebEngineCToCpp() {
}

template <>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkWebEngineCToCpp, ArkWebEngine,
                                        ark_web_engine_t>::kBridgeType =
    ARK_WEB_ENGINE;

} // namespace OHOS::ArkWeb
