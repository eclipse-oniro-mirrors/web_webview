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

#ifndef ARK_FLOWBUFFER_ADAPTER_H
#define ARK_FLOWBUFFER_ADAPTER_H

#include <cstdint>
#include <cstdio>

#include "base/include/ark_web_base_ref_counted.h"
#include "base/include/ark_web_types.h"

namespace OHOS::ArkWeb {

/*--ark web(source=library)--*/
class ArkFlowbufferAdapter : public virtual ArkWebBaseRefCounted {
public:
  /*--ark web()--*/
  ArkFlowbufferAdapter() = default;

  /*--ark web()--*/
  virtual ~ArkFlowbufferAdapter() = default;

  /*--ark web()--*/
  virtual void StartPerformanceBoost() = 0;

  /*--ark web()--*/
  virtual void *CreateAshmem(size_t size, int mapType, int &fd) = 0;

  /*--ark web()--*/
  virtual void *CreateAshmemWithFd(const int fd, size_t size, int mapType) = 0;
};
} // namespace OHOS::ArkWeb

#endif // ARK_FLOWBUFFER_ADAPTER_H