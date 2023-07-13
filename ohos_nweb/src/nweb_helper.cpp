/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "nweb_helper.h"

#include <cstdint>
#include <dirent.h>
#include <dlfcn.h>
#include <memory>
#include <refbase.h>
#include <surface.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <fcntl.h>

#include "config_policy_utils.h"
#include "nweb_adapter_helper.h"
#include "nweb_enhance_surface_adapter.h"
#include "nweb_log.h"
#include "nweb_surface_adapter.h"

namespace {
const uint32_t NWEB_SURFACE_MAX_WIDTH = 7680;
const uint32_t NWEB_SURFACE_MAX_HEIGHT = 7680;
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
const std::string LIB_NAME_WEB_ENGINE = "libweb_engine.so";
static bool g_isFirstTimeStartUp = false;
const std::string WEB_CONFIG_PATH = "etc/web/web_config.xml";
}

namespace OHOS::NWeb {
NWebHelper &NWebHelper::Instance()
{
    static NWebHelper helper;
    return helper;
}

#ifdef __MUSL__
bool NWebHelper::LoadLib(bool from_ark)
{
    if (libHandleWebEngine_ != nullptr) {
        return true;
    }
    if (bundlePath_.empty()) {
        return false;
    }
    std::string loadLibPath;
    if (from_ark) {
        loadLibPath = bundlePath_ + "/" + RELATIVE_PATH_FOR_BUNDLE;
    } else {
        loadLibPath = bundlePath_ + "/" + RELATIVE_PATH_FOR_MOCK;
    }
    Dl_namespace dlns;
    dlns_init(&dlns, "nweb_ns");
    dlns_create(&dlns, loadLibPath.c_str());
    void *libHandleWebEngine = dlopen_ns(&dlns, LIB_NAME_WEB_ENGINE.c_str(), RTLD_NOW);
    if (libHandleWebEngine == nullptr) {
        WVLOG_E("fail to dlopen %{public}s, errmsg=%{public}s", LIB_NAME_WEB_ENGINE.c_str(), dlerror());
        return false;
    }
    libHandleWebEngine_ = libHandleWebEngine;
    return true;
}
#else
bool NWebHelper::LoadLib(bool from_ark)
{
    if (libHandleWebEngine_ != nullptr) {
        return true;
    }
    if (bundlePath_.empty()) {
        return false;
    }
    std::string loadLibPath;
    if (from_ark) {
        loadLibPath = bundlePath_ + "/" + RELATIVE_PATH_FOR_BUNDLE;
    } else {
        loadLibPath = bundlePath_ + "/" + RELATIVE_PATH_FOR_MOCK;
    }
    const std::string libPathWebEngine = loadLibPath + "/" + LIB_NAME_WEB_ENGINE;
    void *libHandleWebEngine = ::dlopen(libPathWebEngine.c_str(), RTLD_NOW);
    if (libHandleWebEngine == nullptr) {
        WVLOG_E("fail to dlopen %{public}s, errmsg=%{public}s", libPathWebEngine.c_str(), dlerror());
        return false;
    }
    libHandleWebEngine_ = libHandleWebEngine;
    return true;
}
#endif

void NWebHelper::UnloadLib()
{
    if (libHandleWebEngine_ != nullptr) {
        ::dlclose(libHandleWebEngine_);
        libHandleWebEngine_ = nullptr;
    }
}

static void DoPreReadLib(const std::string &bundlePath)
{
    WVLOG_I("NWebHelper PreReadLib");
    std::string libPathWebEngine = bundlePath + "/" + RELATIVE_PATH_FOR_BUNDLE + "/" + LIB_NAME_WEB_ENGINE;

    char tempPath[PATH_MAX] = {0};
    if (realpath(libPathWebEngine.c_str(), tempPath) == nullptr) {
        WVLOG_E("path to realpath error");
        return;
    }

    struct stat stats;
    int ret = stat(tempPath, &stats);
    if (ret < 0) {
        WVLOG_E("stat web engine library failed, ret = %{public}d", ret);
        return;
    }

    static const int SINGLE_READ_SIZE = 5 * 1024 * 1024;
    char *buf = new (std::nothrow) char[SINGLE_READ_SIZE];
    if (buf == nullptr) {
        WVLOG_E("malloc buf failed");
        return;
    }

    int fd = open(tempPath, O_RDONLY);
    if (fd <= 0) {
        WVLOG_E("open web engine library failed");
        delete [] buf;
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
    delete [] buf;
    WVLOG_I("NWebHelper PreReadLib Finish");
}

void NWebHelper::TryPreReadLib(bool isFirstTimeStartUpWeb, const std::string &bundlePath)
{
    g_isFirstTimeStartUp = isFirstTimeStartUpWeb;
    if (isFirstTimeStartUpWeb) {
        WVLOG_I("first time startup, need to wait until the nweb init stage");
        return;
    }

    DoPreReadLib(bundlePath);
}

static void TryPreReadLibForFirstlyAppStartUp(const std::string &bundlePath)
{
    if (g_isFirstTimeStartUp) {
        std::thread preReadThread([bundlePath]() {
            DoPreReadLib(bundlePath);
        });

        preReadThread.detach();
    }
}

bool NWebHelper::Init(bool from_ark)
{
    TryPreReadLibForFirstlyAppStartUp(bundlePath_);
    return LoadLib(from_ark);
}

void NWebHelper::SetBundlePath(const std::string &path)
{
    bundlePath_ = path;
}

NWebHelper::~NWebHelper()
{
    UnloadLib();
}

using CreateNWebFuncType = void(*)(const NWebCreateInfo &, std::shared_ptr<NWeb> &);
std::shared_ptr<NWeb> NWebHelper::CreateNWeb(const NWebCreateInfo &create_info)
{
    if (libHandleWebEngine_ == nullptr) {
        WVLOG_E("libHandleWebEngine_ is nullptr");
        return nullptr;
    }

    const std::string CREATE_NWEB_FUNC_NAME = "CreateNWeb";
    CreateNWebFuncType funcCreateNWeb =
        reinterpret_cast<CreateNWebFuncType>(dlsym(libHandleWebEngine_, CREATE_NWEB_FUNC_NAME.c_str()));
    if (funcCreateNWeb == nullptr) {
        WVLOG_E("fail to dlsym %{public}s from libohoswebview.so", CREATE_NWEB_FUNC_NAME.c_str());
        return nullptr;
    }
    std::shared_ptr<NWeb> nweb;
    funcCreateNWeb(create_info, nweb);
    if (nweb == nullptr) {
        WVLOG_E("fail to create nweb");
        return nullptr;
    }

    return nweb;
}

using GetCookieManagerFunc = NWebCookieManager *(*)();
NWebCookieManager *NWebHelper::GetCookieManager()
{
    if (libHandleWebEngine_ == nullptr) {
        WVLOG_E("libHandleWebEngine_ is nullptr");
        return nullptr;
    }

    const std::string COOKIE_FUNC_NAME = "GetCookieManager";
    GetCookieManagerFunc cookieFunc =
        reinterpret_cast<GetCookieManagerFunc>(dlsym(libHandleWebEngine_, COOKIE_FUNC_NAME.c_str()));
    if (cookieFunc == nullptr) {
        WVLOG_E("fail to dlsym %{public}s from libohoswebview.so", COOKIE_FUNC_NAME.c_str());
        return nullptr;
    }
    return cookieFunc();
}

using GetNWebFunc = void(*)(int32_t, std::weak_ptr<NWeb> &);
std::weak_ptr<NWeb> NWebHelper::GetNWeb(int32_t nweb_id)
{
    std::weak_ptr<OHOS::NWeb::NWeb> nweb;
    if (libHandleWebEngine_ == nullptr) {
        WVLOG_E("libHandleWebEngine_ is nullptr");
        return nweb;
    }

    const std::string GET_NWEB_FUNC_NAME = "GetNWeb";
    GetNWebFunc getNWebFunc = reinterpret_cast<GetNWebFunc>(dlsym(libHandleWebEngine_, GET_NWEB_FUNC_NAME.c_str()));
    if (getNWebFunc == nullptr) {
        WVLOG_E("fail to dlsym %{public}s from libohoswebview.so", GET_NWEB_FUNC_NAME.c_str());
        return nweb;
    }

    getNWebFunc(nweb_id, nweb);
    return nweb;
}

using SetHttpDnsFunc = void (*)(const NWebDOHConfig &);
void NWebHelper::SetHttpDns(const NWebDOHConfig &config)
{
    if (libHandleWebEngine_ == nullptr) {
        WVLOG_E("doh: libHandleNWebAdapter_ is nullptr");
        return;
    }

    const std::string SET_HTTP_DNS_FUNC_NAME = "SetHttpDns";
    SetHttpDnsFunc setHttpDnsFunc =
        reinterpret_cast<SetHttpDnsFunc>(dlsym(libHandleWebEngine_, SET_HTTP_DNS_FUNC_NAME.c_str()));
    if (setHttpDnsFunc == nullptr) {
        WVLOG_E("doh: fail to dlsym %{public}s from libohoswebview.so", SET_HTTP_DNS_FUNC_NAME.c_str());
        return;
    }

    setHttpDnsFunc(config);
}

using PrepareForPageLoadFunc = void (*)(std::string, bool, int32_t);
void NWebHelper::PrepareForPageLoad(std::string url, bool preconnectable, int32_t numSockets)
{
    if (libHandleWebEngine_ == nullptr) {
        WVLOG_E("libHandleNWebAdapter_ is nullptr");
        return;
    }
    const std::string PREPARE_FOR_PAGE_LOAD_FUNC_NAME = "PrepareForPageLoad";
    PrepareForPageLoadFunc prepareForPageLoadFunc =
        reinterpret_cast<PrepareForPageLoadFunc>(dlsym(libHandleWebEngine_, PREPARE_FOR_PAGE_LOAD_FUNC_NAME.c_str()));
    if (prepareForPageLoadFunc == nullptr) {
        WVLOG_E("fail to dlsym %{public}s from libohoswebview.so", PREPARE_FOR_PAGE_LOAD_FUNC_NAME.c_str());
        return;
    }
    prepareForPageLoadFunc(url, preconnectable, numSockets);
}

using GetDataBaseFunc = NWebDataBase *(*)();
NWebDataBase *NWebHelper::GetDataBase()
{
    if (libHandleWebEngine_ == nullptr) {
        WVLOG_E("libHandleWebEngine_ is nullptr");
        return nullptr;
    }

    const std::string DATA_BASE_FUNC_NAME = "GetDataBase";
    GetDataBaseFunc dataBaseFunc =
        reinterpret_cast<GetDataBaseFunc>(dlsym(libHandleWebEngine_, DATA_BASE_FUNC_NAME.c_str()));
    if (dataBaseFunc == nullptr) {
        WVLOG_E("fail to dlsym %{public}s from libohoswebview.so", DATA_BASE_FUNC_NAME.c_str());
        return nullptr;
    }
    return dataBaseFunc();
}

using GetWebStorageFunc = NWebWebStorage *(*)();
NWebWebStorage *NWebHelper::GetWebStorage()
{
    if (libHandleWebEngine_ == nullptr) {
        WVLOG_E("libHandleWebEngine_ is nullptr");
        return nullptr;
    }
    const std::string STORAGE_FUNC_NAME = "GetWebStorage";
    GetWebStorageFunc storageFunc =
        reinterpret_cast<GetWebStorageFunc>(dlsym(libHandleWebEngine_, STORAGE_FUNC_NAME.c_str()));
    if (storageFunc == nullptr) {
        WVLOG_E("fail to dlsym %{public}s from libohoswebview.so", STORAGE_FUNC_NAME.c_str());
        return nullptr;
    }
    return storageFunc();
}

NWebAdapterHelper &NWebAdapterHelper::Instance()
{
    static NWebAdapterHelper helper;
    return helper;
}

bool NWebAdapterHelper::Init(bool from_ark)
{
    return NWebHelper::Instance().Init(from_ark);
}

std::shared_ptr<NWeb> NWebAdapterHelper::CreateNWeb(
    sptr<Surface> surface, const NWebInitArgs& initArgs, uint32_t width, uint32_t height)
{
    if (surface == nullptr) {
        WVLOG_E("fail to create nweb, input surface is nullptr");
        return nullptr;
    }
    if (width > NWEB_SURFACE_MAX_WIDTH || height > NWEB_SURFACE_MAX_HEIGHT) {
        WVLOG_E("input size %{public}u*%{public}u is invalid.", width, height);
        return nullptr;
    }
    auto createInfo = NWebSurfaceAdapter::Instance().GetCreateInfo(surface, initArgs, width, height);
    ParseConfig(createInfo);
    auto nweb = NWebHelper::Instance().CreateNWeb(createInfo);
    if (nweb == nullptr) {
        WVLOG_E("fail to create nweb instance");
    }
    return nweb;
}

std::shared_ptr<NWeb> NWebAdapterHelper::CreateNWeb(void *enhanceSurfaceInfo,
                                                    const NWebInitArgs &initArgs,
                                                    uint32_t width,
                                                    uint32_t height)
{
    if (enhanceSurfaceInfo == nullptr) {
        WVLOG_E("fail to create nweb, input surface is nullptr");
        return nullptr;
    }
    if (width > NWEB_SURFACE_MAX_WIDTH || height > NWEB_SURFACE_MAX_HEIGHT) {
        WVLOG_E("input size %{public}u*%{public}u is invalid.", width, height);
        return nullptr;
    }
    auto createInfo = NWebEnhanceSurfaceAdapter::Instance().GetCreateInfo(enhanceSurfaceInfo, initArgs, width, height);
    auto nweb = NWebHelper::Instance().CreateNWeb(createInfo);
    if (nweb == nullptr) {
        WVLOG_E("fail to create nweb instance");
    }
    return nweb;
}

std::string NWebAdapterHelper::GetConfigPath(const std::string& configFileName)
{
    char buf[PATH_MAX + 1];
    char* configPath = GetOneCfgFile(configFileName.c_str(), buf, PATH_MAX + 1);
    char tmpPath[PATH_MAX + 1] = { 0 };
    if (!configPath || strlen(configPath) == 0 || strlen(configPath) > PATH_MAX || !realpath(configPath, tmpPath)) {
        WVLOG_I("can not get customization config file");
        return "/system/" + configFileName;
    }
    return std::string(tmpPath);
}

void NWebAdapterHelper::ReadConfig(const xmlNodePtr& rootPtr, NWebCreateInfo& createInfo)
{
    for (xmlNodePtr curNodePtr = rootPtr->xmlChildrenNode; curNodePtr != nullptr; curNodePtr = curNodePtr->next) {
        if (curNodePtr->name == nullptr || curNodePtr->type == XML_COMMENT_NODE) {
            WVLOG_E("invalid node!");
            continue;
        }
        std::string nodeName = reinterpret_cast<const char*>(curNodePtr->name);
        for (xmlNodePtr curChildNodePtr = curNodePtr->xmlChildrenNode; curChildNodePtr != nullptr;
             curChildNodePtr = curChildNodePtr->next) {
            if (curChildNodePtr->name == nullptr || curChildNodePtr->type == XML_COMMENT_NODE) {
                WVLOG_E("invalid node!");
                continue;
            }
            std::string childNodeName = reinterpret_cast<const char*>(curChildNodePtr->name);
            xmlChar* content = xmlNodeGetContent(curChildNodePtr);
            if (content == nullptr) {
                WVLOG_E("read xml node error: nodeName:(%{public}s)", curChildNodePtr->name);
                continue;
            }
            std::string contentStr = reinterpret_cast<const char*>(content);
            xmlFree(content);
            if (nodeName == std::string("renderConfig") && childNodeName == std::string("renderProcessCount")) {
                createInfo.init_args.web_engine_args_to_add.emplace_back(
                    std::string("--renderer-process-limit=") + contentStr);
                continue;
            }
            if (nodeName == std::string("mediaConfig") &&
                childNodeName == std::string("backgroundMediaShouldSuspend") && contentStr == std::string("false")) {
                createInfo.init_args.web_engine_args_to_add.emplace_back(
                    std::string("--disable-background-media-suspend"));
            }
        }
    }
}

void NWebAdapterHelper::ParseConfig(NWebCreateInfo& createInfo)
{
    auto configFilePath = GetConfigPath(WEB_CONFIG_PATH);
    xmlDocPtr docPtr = xmlReadFile(configFilePath.c_str(), nullptr, XML_PARSE_NOBLANKS);
    if (docPtr == nullptr) {
        WVLOG_E("load xml error!");
        return;
    }

    xmlNodePtr rootPtr = xmlDocGetRootElement(docPtr);
    if (rootPtr == nullptr || rootPtr->name == nullptr ||
        xmlStrcmp(rootPtr->name, reinterpret_cast<const xmlChar*>("WEB"))) {
        WVLOG_E("get root element failed!");
        xmlFreeDoc(docPtr);
        return;
    }

    ReadConfig(rootPtr, createInfo);
    xmlFreeDoc(docPtr);
}
} // namespace OHOS::NWeb
