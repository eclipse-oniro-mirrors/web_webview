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

#include "base/bridge/ark_web_bridge_helper.h"
#include "base/bridge/ark_web_bridge_macros.h"
#include <dlfcn.h>

namespace OHOS::ArkWeb {

#if defined(webview_arm64)
const std::string RELATIVE_PATH_FOR_MOCK = "libs/arm64";
const std::string RELATIVE_PATH_FOR_BUNDLE = "nweb/libs/arm64";
#elif defined(webview_x86_64)
const std::string RELATIVE_PATH_FOR_MOCK = "libs/x86_64";
const std::string RELATIVE_PATH_FOR_BUNDLE = "nweb/libs/x86_64";
#else
const std::string RELATIVE_PATH_FOR_MOCK = "libs/arm";
const std::string RELATIVE_PATH_FOR_BUNDLE = "nweb/libs/arm";
#endif

ArkWebBridgeHelper::~ArkWebBridgeHelper() {
  UnloadLibFile();
}

std::string ArkWebBridgeHelper::GetDirPath(bool runMode,
                                           const std::string &baseDir) {
  if (runMode) {
    return baseDir + "/" + RELATIVE_PATH_FOR_BUNDLE;
  }

  return baseDir + "/" + RELATIVE_PATH_FOR_MOCK;
}

#ifdef __MUSL__
bool ArkWebBridgeHelper::LoadLibFile(bool runMode, const std::string &libNsName,
                                     const std::string &libDirPath,
                                     const std::string &libFileName) {
  Dl_namespace dlns;
  dlns_init(&dlns, libNsName.c_str());

  std::string dirPath = GetDirPath(runMode, libDirPath);
  dlns_create(&dlns, dirPath.c_str());

  void *libFileHandler =
      dlopen_ns(&dlns, libFileName.c_str(), RTLD_NOW | RTLD_GLOBAL);
  if (!libFileHandler) {
    ARK_WEB_WRAPPER_ERROR_LOG("failed to load lib file,lib file name is "
                              "%{public}s,lib dir name is %{public}s",
                              libFileName.c_str(), dirPath.c_str());
    return false;
  }

  libFileHandler_ = libFileHandler;
  return true;
}
#else
bool ArkWebBridgeHelper::LoadLibFile(bool runMode,
                                     const std::string &libDirPath,
                                     const std::string &libFileName) {
  std::string dirPath = GetDirPath(runMode, libDirPath);
  std::string libFilePath = dirPath + "/" + libFileName;
  void *libFileHandler = ::dlopen(libFilePath.c_str(), RTLD_NOW);
  if (!libFileHandler) {
    ARK_WEB_WRAPPER_ERROR_LOG(
        "failed to load lib file,lib file path is %{public}s",
        libFilePath.c_str());
    return false;
  }

  libFileHandler_ = libFileHandler;
  return true;
}
#endif

void ArkWebBridgeHelper::UnloadLibFile() {
  if (libFileHandler_ != nullptr) {
    ::dlclose(libFileHandler_);
    libFileHandler_ = nullptr;
  }
}

void *ArkWebBridgeHelper::LoadFuncSymbol(const std::string &funcName) {
  if (!libFileHandler_) {
    ARK_WEB_WRAPPER_ERROR_LOG(
        "lib file handle is nullptr,func name is %{public}s", funcName.c_str());
    return nullptr;
  }

  ARK_WEB_WRAPPER_INFO_LOG("load func %{public}s", funcName.c_str());
  return dlsym(libFileHandler_, funcName.c_str());
}

} // namespace OHOS::ArkWeb
