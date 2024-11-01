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

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base/bridge/ark_web_bridge_macros.h"

namespace OHOS::ArkWeb {

int g_ark_web_init_addr = 1;

ArkWebBridgeHelper::~ArkWebBridgeHelper()
{
    UnloadLibFile();
}

bool ArkWebBridgeHelper::LoadLibFile(int openMode, const std::string& libFilePath, bool isPrintLog)
{
    if (libFileHandler_) {
        return true;
    }

    void* libFileHandler = ::dlopen(libFilePath.c_str(), openMode);
    if (!libFileHandler) {
        if (isPrintLog) {
            ARK_WEB_BRIDGE_ERROR_LOG("failed to load lib file %{public}s", libFilePath.c_str());
        }

        return false;
    }

    if (isPrintLog) {
        ARK_WEB_BRIDGE_INFO_LOG("succeed to load lib file %{public}s", libFilePath.c_str());
    }

    libFileHandler_ = libFileHandler;
    return true;
}

#if defined(OHOS_WEBVIEW_GLUE)
bool ArkWebBridgeHelper::LoadLibFile(int openMode, const std::string& libNsName, const std::string& libDirPath,
    const std::string& libFileName, bool isPrintLog)
{
    if (libFileHandler_) {
        return true;
    }

    Dl_namespace dlns;
    dlns_init(&dlns, libNsName.c_str());
    dlns_create(&dlns, libDirPath.c_str());

    Dl_namespace ndkns;
    dln_get("ndkns", &ndkns);
    dlns_inherit(&dlns, &ndkns, "allow_all_shared_libs")

    void* libFileHandler = dlopen_ns(&dlns, libFileName.c_str(), openMode);
    if (!libFileHandler) {
        if (isPrintLog) {
            ARK_WEB_BRIDGE_ERROR_LOG(
                "failed to load lib file %{public}s/%{public}s", libDirPath.c_str(), libFileName.c_str());
        }

        return false;
    }

    if (isPrintLog) {
        ARK_WEB_BRIDGE_INFO_LOG(
            "succeed to load lib file %{public}s/%{public}s", libDirPath.c_str(), libFileName.c_str());
    }

    libFileHandler_ = libFileHandler;
    return true;
}
#endif

void ArkWebBridgeHelper::UnloadLibFile()
{
    if (libFileHandler_ != nullptr) {
        ::dlclose(libFileHandler_);
        libFileHandler_ = nullptr;
    }
}

void ArkWebBridgeHelper::PrereadLibFile(const std::string& libFilePath, bool isPrintLog)
{
    char realPath[PATH_MAX] = { 0 };
    if (realpath(libFilePath.c_str(), realPath) == nullptr) {
        if (isPrintLog) {
            ARK_WEB_BRIDGE_ERROR_LOG("failed to get real path,lib file is %{public}s,errno is %{public}d(%{public}s)",
                libFilePath.c_str(), errno, strerror(errno));
        }
        return;
    }

    struct stat stats;
    if (stat(realPath, &stats) < 0) {
        if (isPrintLog) {
            ARK_WEB_BRIDGE_ERROR_LOG("failed to stat lib file %{public}s,errno is %{public}d(%{public}s)",
                libFilePath.c_str(), errno, strerror(errno));
        }
        return;
    }

    int fd = open(realPath, O_RDONLY);
    if (fd <= 0) {
        if (isPrintLog) {
            ARK_WEB_BRIDGE_ERROR_LOG("failed to open lib file %{public}s,errno is %{public}d : %{public}s",
                libFilePath.c_str(), errno, strerror(errno));
        }
        return;
    }

    static const int SINGLE_READ_SIZE = 5 * 1024 * 1024;
    char* buf = new (std::nothrow) char[SINGLE_READ_SIZE];
    if (buf == nullptr) {
        (void)close(fd);
        if (isPrintLog) {
            ARK_WEB_BRIDGE_ERROR_LOG("failed to malloc buf,lib file is %{public}s", libFilePath.c_str());
        }
        return;
    }

    int readCnt = stats.st_size / SINGLE_READ_SIZE;
    if (readCnt * SINGLE_READ_SIZE < stats.st_size) {
        readCnt += 1;
    }

    for (int i = 0; i < readCnt; i++) {
        (void)read(fd, buf, SINGLE_READ_SIZE);
    }

    (void)close(fd);
    delete[] buf;

    if (isPrintLog) {
        ARK_WEB_BRIDGE_INFO_LOG("succeed to preread lib file %{public}s", libFilePath.c_str());
    }
}

void* ArkWebBridgeHelper::LoadFuncSymbol(const char* funcName, bool isPrintLog)
{
    if (!libFileHandler_) {
        if (isPrintLog) {
            ARK_WEB_BRIDGE_ERROR_LOG("lib file handle is nullptr,func name is %{public}s", funcName);
        }

        return nullptr;
    }

    if (isPrintLog) {
        ARK_WEB_BRIDGE_INFO_LOG("load func %{public}s", funcName);
    }

    return dlsym(libFileHandler_, funcName);
}

void ArkWebBridgeHelper::InitFuncMemberMaps(ArkWebBridgeType init, ArkWebBridgeType butt, bool isPrintLog)
{
    std::map<std::string, void*> funcMemberMap;
    for (int type = static_cast<int>(init); type < static_cast<int>(butt); type++) {
        funcMemberMaps_[type] = funcMemberMap;
    }

    if (isPrintLog) {
        ARK_WEB_BRIDGE_DV_LOG("init func member maps,bridge type is %{public}d - %{public}d", init, butt);
    }
}

void ArkWebBridgeHelper::RegisterFuncMember(
    ArkWebBridgeType bridgeType, const std::map<std::string, void*>& funcMemberMap)
{
    auto itor = funcMemberMaps_.find(static_cast<int>(bridgeType));
    if (itor == funcMemberMaps_.end()) {
        ARK_WEB_BRIDGE_INFO_LOG("func member map isn't exist,bridge type is %{public}d", bridgeType);
        return;
    }

    itor->second = funcMemberMap;
    ARK_WEB_BRIDGE_DV_LOG("func member map is registered and bridge type is %{public}d", bridgeType);
}

void* ArkWebBridgeHelper::CheckFuncMemberForCalled(ArkWebBridgeType bridgeType, const std::string& funcName)
{
    if (funcName.empty()) {
        ARK_WEB_BRIDGE_INFO_LOG("func name is empty,bridge ype is %{public}d", bridgeType);
        return nullptr;
    }

    auto itor0 = funcMemberMaps_.find(static_cast<int>(bridgeType));
    if (itor0 == funcMemberMaps_.end()) {
        ARK_WEB_BRIDGE_INFO_LOG("func member map isn't registered,bridge type is %{public}d,func name is %{public}s",
            bridgeType, funcName.c_str());
        return nullptr;
    }

    auto itor1 = itor0->second.find(funcName);
    if (itor1 == itor0->second.end()) {
        ARK_WEB_BRIDGE_INFO_LOG("func member isn't registered,bridge type is %{public}d,func name is %{public}s",
            bridgeType, funcName.c_str());
        return nullptr;
    }

    return itor1->second;
}

void* ArkWebBridgeHelper::CheckFuncMemberForCaller(ArkWebBridgeType bridgeType, const std::string& funcName)
{
    if (!memberCheckFunc_) {
        return ARK_WEB_INIT_ADDR;
    }

    ArkWebString stFuncName = ArkWebStringClassToStruct(funcName);
    void* func = memberCheckFunc_(bridgeType, &stFuncName);
    ArkWebStringStructRelease(stFuncName);
    return func;
}

} // namespace OHOS::ArkWeb
