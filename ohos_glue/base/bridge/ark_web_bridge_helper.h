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

#ifndef ARK_WEB_BRIDGE_HELPER_H_
#define ARK_WEB_BRIDGE_HELPER_H_
#pragma once

#include <string>

namespace OHOS::ArkWeb {

class ArkWebBridgeHelper {
public:
  virtual ~ArkWebBridgeHelper();

  virtual bool Init(bool runMode, const std::string &baseDir) = 0;

  void *LoadFuncSymbol(const std::string &funcName);

protected:
  ArkWebBridgeHelper() = default;

#ifdef __MUSL__
  bool LoadLibFile(bool runMode, const std::string &libNsName,
                   const std::string &libDirPath,
                   const std::string &libFileName);
#else
  bool LoadLibFile(bool runMode, const std::string &libDirPath,
                   const std::string &libFileName);
#endif

private:
  std::string GetDirPath(bool runMode, const std::string &baseDir);

  void UnloadLibFile();

  void *libFileHandler_;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_BRIDGE_HELPER_H_
