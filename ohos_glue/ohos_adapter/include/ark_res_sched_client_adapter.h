/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef ARK_RES_SCHED_CLIENT_ADAPTER_H
#define ARK_RES_SCHED_CLIENT_ADAPTER_H

#include <cstdint>
#include <unistd.h>

#include "include/ark_web_base_ref_counted.h"

namespace OHOS::ArkWeb {

/*--web engine(source=library)--*/
class ArkResSchedClientAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkResSchedClientAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkResSchedClientAdapter() = default;

    /*--web engine()--*/
    static bool ReportKeyThread(int32_t statusAdapter, pid_t pid, pid_t tid, int32_t roleAdapter);

    /*--web engine()--*/
    static bool ReportWindowStatus(int32_t statusAdapter, pid_t pid, uint32_t windowId, int32_t nwebId);

    /*--web engine()--*/
    static bool ReportScene(int32_t statusAdapter, int32_t sceneAdapter, int32_t nwebId);

    /*--web engine()--*/
    static bool ReportAudioData(int32_t statusAdapter, pid_t pid, pid_t tid);

    /*--web engine()--*/
    static void ReportWindowId(int32_t windowId, int32_t nwebId);

    /*--web engine()--*/
    static void ReportNWebInit(int32_t statusAdapter, int32_t nweb_id);

    /*--web engine()--*/
    static void ReportRenderProcessStatus(int32_t statusAdapter, pid_t pid);

    /*--web engine()--*/
    static bool ReportScreenCapture(int32_t statusAdapter, pid_t pid);

    /*--web engine()--*/
    static bool ReportVideoPlaying(int32_t statusAdapter, pid_t pid);
};
} // namespace OHOS::ArkWeb

#endif // ARK_RES_SCHED_CLIENT_ADAPTER_H
