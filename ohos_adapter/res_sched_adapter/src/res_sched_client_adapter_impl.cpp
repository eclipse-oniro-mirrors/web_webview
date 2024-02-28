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

#include <mutex>
#include <set>
#include <string>
#include <unistd.h>
#include <vector>

#include "app_mgr_constants.h"
#include "app_mgr_client.h"
#include "bundle_mgr_interface.h"
#include "iservice_registry.h"
#include "nweb_log.h"
#include "res_sched_client.h"
#include "res_sched_client_adapter.h"
#include "res_type.h"
#include "system_ability_definition.h"

namespace OHOS::NWeb {
using namespace OHOS::ResourceSchedule;

const std::unordered_map<ResSchedTypeAdapter, uint32_t> RES_TYPE_MAP = {
    { ResSchedTypeAdapter::RES_TYPE_KEY_THREAD, ResType::RES_TYPE_REPORT_KEY_THREAD },
    { ResSchedTypeAdapter::RES_TYPE_WEB_STATUS_CHANGE, ResType::RES_TYPE_REPORT_WINDOW_STATE },
    { ResSchedTypeAdapter::RES_TYPE_WEB_SCENE, ResType::RES_TYPE_REPORT_SCENE_SCHED },
    { ResSchedTypeAdapter::RES_TYPE_WEBVIEW_AUDIO_STATUS_CHANGE, ResType::RES_TYPE_WEBVIEW_AUDIO_STATUS_CHANGE },
};

const std::unordered_map<ResSchedStatusAdapter, int64_t> RES_STATUS_MAP = {
    { ResSchedStatusAdapter::THREAD_CREATED, ResType::ReportChangeStatus::CREATE },
    { ResSchedStatusAdapter::THREAD_DESTROYED, ResType::ReportChangeStatus::REMOVE },
    { ResSchedStatusAdapter::WEB_ACTIVE, ResType::WindowStates::ACTIVE },
    { ResSchedStatusAdapter::WEB_INACTIVE, ResType::WindowStates::INACTIVE },
    { ResSchedStatusAdapter::WEB_SCENE_ENTER, ResType::SceneControl::SCENE_IN },
    { ResSchedStatusAdapter::WEB_SCENE_EXIT, ResType::SceneControl::SCENE_OUT },
    { ResSchedStatusAdapter::AUDIO_STATUS_START, ResType::AudioStatus::START },
    { ResSchedStatusAdapter::AUDIO_STATUS_STOP, ResType::AudioStatus::STOP },
};

const std::unordered_map<ResSchedRoleAdapter, ResType::ThreadRole> RES_ROLE_MAP = {
    { ResSchedRoleAdapter::USER_INTERACT, ResType::ThreadRole::USER_INTERACT },
    { ResSchedRoleAdapter::NORMAL_DISPLAY, ResType::ThreadRole::NORMAL_DISPLAY },
    { ResSchedRoleAdapter::IMPORTANT_DISPLAY, ResType::ThreadRole::IMPORTANT_DISPLAY },
    { ResSchedRoleAdapter::NORMAL_AUDIO, ResType::ThreadRole::NORMAL_AUDIO },
    { ResSchedRoleAdapter::IMPORTANT_AUDIO, ResType::ThreadRole::IMPORTANT_AUDIO },
};

const std::unordered_map<ResSchedSceneAdapter, int32_t> RES_SCENE_MAP = {
    { ResSchedSceneAdapter::LOAD_URL, ResType::WebScene::WEB_SCENE_LOAD_URL },
    { ResSchedSceneAdapter::CLICK, ResType::WebScene::WEB_SCENE_CLICK },
    { ResSchedSceneAdapter::SLIDE, ResType::WebScene::WEB_SCENE_SLIDE },
    { ResSchedSceneAdapter::RESIZE, ResType::WebScene::WEB_SCENE_RESIZE },
    { ResSchedSceneAdapter::VISIBLE, ResType::WebScene::WEB_SCENE_VISIBLE },
    { ResSchedSceneAdapter::KEYBOARD_CLICK, ResType::WebScene::WEB_SCENE_KEYBOARD_CLICK },
};

const int32_t INVALID_NUMBER = -1;
const int64_t INVALID_NUMBER_INT64 = -1;
const pid_t INVALID_PID = -1;
constexpr char PID[] = "pid";
constexpr char UID[] = "uid";
constexpr char TID[] = "tid";
constexpr char ROLE[] = "role";
constexpr char WINDOW_ID[] = "windowId";
constexpr char SERIAL_NUMBER[] = "serialNum";
constexpr char SCENE_ID[] = "sceneId";
constexpr char STATE[] = "state";
std::set<int32_t> g_nwebSet;
std::mutex g_windowIdMutex {};
int32_t g_windowId = INVALID_NUMBER;
int32_t g_nwebId = INVALID_NUMBER;
pid_t g_lastPid = INVALID_PID;
int64_t g_lastStatus = INVALID_NUMBER_INT64;

std::string GetUidString()
{
    static std::string uidString = std::to_string(getuid());
    return uidString;
}

std::string GetBundleNameByUid(int32_t uid)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        WVLOG_E("get SystemAbilityManager failed");
        return "";
    }
    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (remoteObject == nullptr) {
        WVLOG_E("get Bundle Manager failed");
        return "";
    }
    auto bundleMgr = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (bundleMgr == nullptr) {
        return "";
    }
    std::string bundle {""};
    bundleMgr->GetNameForUid(uid, bundle);
    return bundle;
}

bool ConvertStatus(ResSchedStatusAdapter statusAdapter, int64_t& status)
{
    if (auto it = RES_STATUS_MAP.find(statusAdapter); it == RES_STATUS_MAP.end()) {
        WVLOG_E("invalid status: %{public}d", statusAdapter);
        return false;
    } else {
        status = it->second;
    }
    return true;
}

bool ReportSceneInternal(ResSchedStatusAdapter statusAdapter, ResSchedSceneAdapter sceneAdapter)
{
    int64_t status;
    bool ret = ConvertStatus(statusAdapter, status);
    if (!ret) {
        return false;
    }

    int32_t sceneId;
    if (auto it = RES_SCENE_MAP.find(sceneAdapter); it == RES_SCENE_MAP.end()) {
        WVLOG_E("invalid scene id: %{public}d", sceneAdapter);
        return false;
    } else {
        sceneId = it->second;
    }

    std::unordered_map<std::string, std::string> mapPayload { { UID, GetUidString() },
        { SCENE_ID, std::to_string(sceneId) } };
    ResSchedClient::GetInstance().ReportData(ResType::RES_TYPE_REPORT_SCENE_SCHED, status, mapPayload);
    WVLOG_D("ReportScene status: %{public}d, uid: %{public}s, sceneId: %{public}d", static_cast<int32_t>(status),
        GetUidString().c_str(), sceneId);
    return true;
}

bool ResSchedClientAdapter::ReportKeyThread(
    ResSchedStatusAdapter statusAdapter, pid_t pid, pid_t tid, ResSchedRoleAdapter roleAdapter)
{
    int64_t status;
    bool ret = ConvertStatus(statusAdapter, status);
    if (!ret) {
        return false;
    }

    ResType::ThreadRole role;
    if (auto it = RES_ROLE_MAP.find(roleAdapter); it == RES_ROLE_MAP.end()) {
        WVLOG_E("invalid role: %{public}d", roleAdapter);
        return false;
    } else {
        role = it->second;
    }

    std::unordered_map<std::string, std::string> mapPayload { { UID, GetUidString() }, { PID, std::to_string(pid) },
        { TID, std::to_string(tid) }, { ROLE, std::to_string(role) } };

    // Report process creation event first when render process is created
    if (pid == tid) {
        mapPayload["processType"] = std::to_string(static_cast<uint32_t>(AppExecFwk::ProcessType::RENDER));
        mapPayload["bundleName"] = GetBundleNameByUid(getuid());
    }

    ResSchedClient::GetInstance().ReportData(ResType::RES_TYPE_REPORT_KEY_THREAD, status, mapPayload);
    WVLOG_D("ReportKeyThread status: %{public}d, uid: %{public}s, pid: %{public}d, tid:%{public}d, role: %{public}d",
        static_cast<int32_t>(status), GetUidString().c_str(), pid, tid, static_cast<int32_t>(role));

    if (pid == tid && g_windowId != INVALID_NUMBER && g_nwebId != INVALID_NUMBER) {
        std::lock_guard<std::mutex> lock(g_windowIdMutex);
        ReportWindowStatus(ResSchedStatusAdapter::WEB_ACTIVE, pid, g_windowId, g_nwebId);
    }

    // Load url may create new render process, repeat report load url event when
    // render key thread create to solve timing problem. Later events will overwrite previous events
    if (statusAdapter == ResSchedStatusAdapter::THREAD_CREATED && pid != getprocpid()) {
        ReportSceneInternal(statusAdapter, ResSchedSceneAdapter::LOAD_URL);
    }
    return true;
}

bool ResSchedClientAdapter::ReportAudioData(ResSchedStatusAdapter statusAdapter, pid_t pid, pid_t tid)
{
    static uint32_t resType = ResType::RES_TYPE_WEBVIEW_AUDIO_STATUS_CHANGE;

    int64_t status;
    if (!ConvertStatus(statusAdapter, status)) {
        return false;
    }

    uid_t uid = getuid();
    std::unordered_map<std::string, std::string> mapPayload { { UID, std::to_string(uid) },
        { PID, std::to_string(pid) }, { TID, std::to_string(tid) } };
    WVLOG_D("ReportAudioData status: %{public}d, uid: %{public}d, pid: %{public}d, tid:%{public}d",
        static_cast<int32_t>(status), uid, pid, tid);
    ResSchedClient::GetInstance().ReportData(resType, status, mapPayload);

    return true;
}

bool ResSchedClientAdapter::ReportWindowStatus(
    ResSchedStatusAdapter statusAdapter, pid_t pid, uint32_t windowId, int32_t nwebId)
{
    static uint32_t serial_num = 0;
    static constexpr uint32_t SERIAL_NUM_MAX = 10000;

    if (g_nwebSet.find(nwebId) == g_nwebSet.end() || pid == 0) {
        WVLOG_D("Don't report window status, nwebId: %{public}d, pid: %{public}d", nwebId, pid);
        return false;
    }

    int64_t status;
    bool ret = ConvertStatus(statusAdapter, status);
    if (!ret) {
        return false;
    }

    if (pid == g_lastPid && status == g_lastStatus) {
        return true;
    }
    g_lastPid = pid;
    g_lastStatus = status;

    std::unordered_map<std::string, std::string> mapPayload { { UID, GetUidString() }, { PID, std::to_string(pid) },
        { WINDOW_ID, std::to_string(windowId) }, { SERIAL_NUMBER, std::to_string(serial_num) },
        { STATE, std::to_string(status) } };
    ResSchedClient::GetInstance().ReportData(
        ResType::RES_TYPE_REPORT_WINDOW_STATE, ResType::ReportChangeStatus::CREATE, mapPayload);
    
    auto appMgrClient = DelayedSingleton<AppExecFwk::appMgrClient>::GetInstance();
    appMgrClient->UpdateRenderState(pid, status);

    WVLOG_D("ReportWindowStatus status: %{public}d, uid: %{public}s, pid: %{public}d, windowId:%{public}d, sn: "
            "%{public}d", static_cast<int32_t>(status), GetUidString().c_str(), pid, windowId, serial_num);
    serial_num = (serial_num + 1) % SERIAL_NUM_MAX;

    // Report visible scene event again when tab becomes active to solve timing problem
    if (statusAdapter == ResSchedStatusAdapter::WEB_ACTIVE) {
        ReportSceneInternal(statusAdapter, ResSchedSceneAdapter::VISIBLE);
    }
    return true;
}

bool ResSchedClientAdapter::ReportScene(
    ResSchedStatusAdapter statusAdapter, ResSchedSceneAdapter sceneAdapter, int32_t nwebId)
{
    if (nwebId == -1) {
        return ReportSceneInternal(statusAdapter, sceneAdapter);
    }

    if (g_nwebSet.find(nwebId) == g_nwebSet.end()) {
        WVLOG_E("ReportScene nwebId %{public}d not exist in render set", nwebId);
        return false;
    }
    return ReportSceneInternal(statusAdapter, sceneAdapter);
}

void ResSchedClientAdapter::ReportWindowId(int32_t windowId, int32_t nwebId)
{
    std::lock_guard<std::mutex> lock(g_windowIdMutex);
    g_windowId = windowId;
    g_nwebId = nwebId;
    WVLOG_D("ReportWindowId windowId: %{public}d, nwebId: %{public}d", g_windowId, g_nwebId);
}

void ResSchedClientAdapter::ReportNWebInit(ResSchedStatusAdapter statusAdapter, int32_t nwebId)
{
    static std::mutex initMutex;
    std::lock_guard<std::mutex> lock(initMutex);
    if (statusAdapter == ResSchedStatusAdapter::WEB_SCENE_ENTER) {
        WVLOG_D("ReportNWebInit %{public}d", nwebId);
        g_nwebSet.emplace(nwebId);
    } else if (statusAdapter == ResSchedStatusAdapter::WEB_SCENE_EXIT) {
        g_nwebSet.erase(nwebId);
    }
}
} // namespace OHOS::NWeb
