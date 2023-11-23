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

#include "application_context.h"
#include "config_policy_utils.h"
#include "nweb_adapter_helper.h"
#include "nweb_enhance_surface_adapter.h"
#include "nweb_log.h"
#include "nweb_surface_adapter.h"

#include "nweb_c_api.h"

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
const std::string INIT_CONFIG = "initConfig";
const std::string PERFORMANCE_CONFIG = "performanceConfig";

// Run DO macro for every function defined in the API.
#define FOR_EACH_API_FN(DO)                          \
    DO(WebDownloadManager_PutDownloadCallback)       \
    DO(WebDownloader_ResumeDownloadStatic)           \
    DO(WebDownloader_StartDownload)                  \
    DO(WebDownloader_CreateDownloadDelegateCallback) \
    DO(WebDownloader_SetDownloadBeforeStart)         \
    DO(WebDownloader_SetDownloadDidUpdate)           \
    DO(WebDownload_Continue)                         \
    DO(WebDownload_Cancel)                           \
    DO(WebDownload_Pause)                            \
    DO(WebDownload_Resume)                           \
    DO(WebDownloadItem_Guid)                         \
    DO(WebDownloadItem_GetDownloadItemId)            \
    DO(WebDownloadItem_GetState)                     \
    DO(WebDownloadItem_CurrentSpeed)                 \
    DO(WebDownloadItem_PercentComplete)              \
    DO(WebDownloadItem_TotalBytes)                   \
    DO(WebDownloadItem_ReceivedBytes)                \
    DO(WebDownloadItem_FullPath)                     \
    DO(WebDownloadItem_Url)                          \
    DO(WebDownloadItem_OriginalUrl)                  \
    DO(WebDownloadItem_SuggestedFileName)            \
    DO(WebDownloadItem_ContentDisposition)           \
    DO(WebDownloadItem_ETag)                         \
    DO(WebDownloadItem_MimeType)                     \
    DO(WebDownloadItem_NWebId)                       \
    DO(WebDownloadItem_IsPaused)                     \
    DO(WebDownloadItem_Method)                       \
    DO(WebDownloadItem_LastErrorCode)                \
    DO(WebDownloadItem_ReceivedSlices)               \
    DO(WebDownloadItem_LastModified)                 \
    DO(WebDownloadItem_CreateWebDownloadItem)        \
    DO(WebDownloadItem_Destroy)                      \
    DO(WebDownloadItem_SetUrl)                       \
    DO(WebDownloadItem_SetFullPath)                  \
    DO(WebDownloadItem_SetETag)                      \
    DO(WebDownloadItem_SetLastModified)              \
    DO(WebDownloadItem_SetMimeType)                  \
    DO(WebDownloadItem_SetReceivedBytes)             \
    DO(WebDownloadItem_SetTotalBytes)                \
    DO(WebDownloadItem_SetReceivedSlices)            \
    DO(WebDownloadItem_SetGuid)                      \
    DO(DestroyBeforeDownloadCallbackWrapper)         \
    DO(DestroyDownloadItemCallbackWrapper)

struct NWebCApi {
    // Generate a function pointer field for every NWeb C API function.
#define GEN_FN_PTR(fn) decltype(&fn) impl_##fn = nullptr;
    FOR_EACH_API_FN(GEN_FN_PTR)
#undef GEN_FN_PTR
};

template <typename Fn> void LoadFunction(void *handle, const char *functionName, Fn *fnOut)
{
    void *fn = dlsym(handle, functionName);
    if (!fn) {
        OHOS::WVLOG_E("%{public}s not found.", functionName);
        return;
    }
    *fnOut = reinterpret_cast<Fn>(fn);
}

NWebCApi *g_nwebCApi = nullptr;

void LoadNWebCApi(void *handle, NWebCApi *api)
{
    // Initialize each NWebExApi function pointer field from the DLL
#define LOAD_FN_PTR(fn) LoadFunction(handle, #fn, &api->impl_##fn);
    FOR_EACH_API_FN(LOAD_FN_PTR)
#undef LOAD_FN_PTR
}

bool LoadNWebSDK(void *handle)
{
    if (g_nwebCApi) {
        OHOS::WVLOG_E("LoadNWebSDK had loaded.");
        return true;
    }

    if (handle == nullptr) {
        OHOS::WVLOG_E("LoadNWebSDK handle is nullptr.");
        return false;
    }

    auto *nwebCApi = new NWebCApi();
    if (nwebCApi == nullptr) {
        OHOS::WVLOG_E("nwebCApi is nullptr.");
        return false;
    }
    LoadNWebCApi(handle, nwebCApi);
    g_nwebCApi = nwebCApi;
    return true;
}
#undef FOR_EACH_API_FN
}

extern "C" void WebDownloadManager_PutDownloadCallback(WebDownloadDelegateCallback *callback)
{
    if (!g_nwebCApi->impl_WebDownloadManager_PutDownloadCallback) {
        OHOS::WVLOG_E("WebDownloadManager_PutDownloadCallback not found.");
        return;
    }
    g_nwebCApi->impl_WebDownloadManager_PutDownloadCallback(callback);
}

extern "C" void WebDownloader_SetDownloadBeforeStart(WebDownloadDelegateCallback *callback, OnDownloadBeforeStart fun)
{
    if (!g_nwebCApi->impl_WebDownloader_SetDownloadBeforeStart) {
        OHOS::WVLOG_E("WebDownloader_SetDownloadBeforeStart not found.");
        return;
    }
    g_nwebCApi->impl_WebDownloader_SetDownloadBeforeStart(callback, fun);
}

extern "C" void WebDownloader_SetDownloadDidUpdate(WebDownloadDelegateCallback *callback, OnDownloadDidUpdate fun)
{
    if (!g_nwebCApi->impl_WebDownloader_SetDownloadDidUpdate) {
        OHOS::WVLOG_E("WebDownloader_SetDownloadDidUpdate not found");
        return;
    }
    g_nwebCApi->impl_WebDownloader_SetDownloadDidUpdate(callback, fun);
}

extern "C" void WebDownloader_ResumeDownloadStatic(const NWebDownloadItem *downloadItem)
{
    if (!g_nwebCApi->impl_WebDownloader_ResumeDownloadStatic) {
        OHOS::WVLOG_E("WebDownloader_ResumeDownloadStatic not found.");
        return;
    }
    g_nwebCApi->impl_WebDownloader_ResumeDownloadStatic(downloadItem);
}

extern "C" void WebDownloader_StartDownload(int32_t nwebId, const char* url)
{
    if (!g_nwebCApi->impl_WebDownloader_StartDownload) {
        OHOS::WVLOG_E("WebDownloader_StartDownload not found.");
        return;
    }
    g_nwebCApi->impl_WebDownloader_StartDownload(nwebId, url);
}

extern "C" void WebDownloader_CreateDownloadDelegateCallback(WebDownloadDelegateCallback **callback)
{
    if (!g_nwebCApi || !g_nwebCApi->impl_WebDownloader_CreateDownloadDelegateCallback) {
        OHOS::WVLOG_E("WebDownloader_CreateDownloadDelegateCallback not found.");
        return;
    }

    return g_nwebCApi->impl_WebDownloader_CreateDownloadDelegateCallback(callback);
}

extern "C" void WebDownload_Continue(const WebBeforeDownloadCallbackWrapper *wrapper, const char *downloadPath)
{
    if (!g_nwebCApi->impl_WebDownload_Continue) {
        OHOS::WVLOG_E("WebDownload_Continue not found.");
        return;
    }
    g_nwebCApi->impl_WebDownload_Continue(wrapper, downloadPath);
}

extern "C" void WebDownload_Cancel(const WebDownloadItemCallbackWrapper *wrapper)
{
    if (!g_nwebCApi->impl_WebDownload_Cancel) {
        OHOS::WVLOG_E("WebDownload_Cancel not found.");
        return;
    }
    g_nwebCApi->impl_WebDownload_Cancel(wrapper);
}

extern "C" void WebDownload_Pause(const WebDownloadItemCallbackWrapper *wrapper)
{
    if (!g_nwebCApi->impl_WebDownload_Pause) {
        OHOS::WVLOG_E("WebDownload_Pause not found");
        return;
    }
    g_nwebCApi->impl_WebDownload_Pause(wrapper);
}

extern "C" void WebDownload_Resume(const WebDownloadItemCallbackWrapper *wrapper)
{
    if (!g_nwebCApi->impl_WebDownload_Resume) {
        OHOS::WVLOG_E("WebDownload_Resume not found.");
        return;
    }
    g_nwebCApi->impl_WebDownload_Resume(wrapper);
}

extern "C" char *WebDownloadItem_Guid(const NWebDownloadItem *downloadItem)
{
    if (!g_nwebCApi->impl_WebDownloadItem_Guid) {
        OHOS::WVLOG_E("WebDownloadItem_Guid not found.");
        return nullptr;
    }
    return g_nwebCApi->impl_WebDownloadItem_Guid(downloadItem);
}

extern "C" long WebDownloadItem_GetDownloadItemId(const NWebDownloadItem *downloadItem)
{
    if (!g_nwebCApi->impl_WebDownloadItem_GetDownloadItemId) {
        return false;
    }
    return g_nwebCApi->impl_WebDownloadItem_GetDownloadItemId(downloadItem);
}

extern "C" NWebDownloadItemState WebDownloadItem_GetState(const NWebDownloadItem *downloadItem)
{
    if (!g_nwebCApi->impl_WebDownloadItem_GetState) {
        return NWebDownloadItemState::MAX_DOWNLOAD_STATE;
    }
    return g_nwebCApi->impl_WebDownloadItem_GetState(downloadItem);
}

extern "C" int WebDownloadItem_CurrentSpeed(const NWebDownloadItem *downloadItem)
{
    if (!g_nwebCApi->impl_WebDownloadItem_CurrentSpeed) {
        OHOS::WVLOG_E("WebDownloadItem_CurrentSpeed not found.");
        return 0;
    }
    return g_nwebCApi->impl_WebDownloadItem_CurrentSpeed(downloadItem);
}

extern "C" int WebDownloadItem_PercentComplete(const NWebDownloadItem *downloadItem)
{
    if (!g_nwebCApi->impl_WebDownloadItem_PercentComplete) {
        OHOS::WVLOG_E("WebDownloadItem_TotalBytes not found.");
        return 0;
    }
    return g_nwebCApi->impl_WebDownloadItem_PercentComplete(downloadItem);
}

extern "C" int64_t WebDownloadItem_TotalBytes(const NWebDownloadItem *downloadItem)
{
    if (!g_nwebCApi->impl_WebDownloadItem_TotalBytes) {
        OHOS::WVLOG_E("WebDownloadItem_TotalBytes not found.");
        return 0;
    }
    return g_nwebCApi->impl_WebDownloadItem_TotalBytes(downloadItem);
}

extern "C" int64_t WebDownloadItem_ReceivedBytes(const NWebDownloadItem *downloadItem)
{
    if (!g_nwebCApi->impl_WebDownloadItem_ReceivedBytes) {
        OHOS::WVLOG_E("WebDownloadItem_ReceivedBytes not found.");
        return 0;
    }
    return g_nwebCApi->impl_WebDownloadItem_ReceivedBytes(downloadItem);
}

extern "C" char *WebDownloadItem_FullPath(const NWebDownloadItem *downloadItem)
{
    if (!g_nwebCApi->impl_WebDownloadItem_FullPath) {
        OHOS::WVLOG_E("WebDownloadItem_FullPath not found");
        return nullptr;
    }
    return g_nwebCApi->impl_WebDownloadItem_FullPath(downloadItem);
}

extern "C" char *WebDownloadItem_Url(const NWebDownloadItem *downloadItem)
{
    if (!g_nwebCApi->impl_WebDownloadItem_Url) {
        OHOS::WVLOG_E("WebDownloadItem_Url not found.");
        return nullptr;
    }
    return g_nwebCApi->impl_WebDownloadItem_Url(downloadItem);
}

extern "C" char *WebDownloadItem_OriginalUrl(const NWebDownloadItem *downloadItem)
{
    if (!g_nwebCApi->impl_WebDownloadItem_OriginalUrl) {
        OHOS::WVLOG_E("WebDownloadItem_OriginalUrl not found.");
        return nullptr;
    }
    return g_nwebCApi->impl_WebDownloadItem_OriginalUrl(downloadItem);
}

extern "C" char *WebDownloadItem_SuggestedFileName(const NWebDownloadItem *downloadItem)
{
    if (!g_nwebCApi->impl_WebDownloadItem_SuggestedFileName) {
        OHOS::WVLOG_E("WebDownloadItem_SuggestedFileName not found.");
        return nullptr;
    }
    return g_nwebCApi->impl_WebDownloadItem_SuggestedFileName(downloadItem);
}

extern "C" char *WebDownloadItem_ContentDisposition(const NWebDownloadItem *downloadItem)
{
    if (!g_nwebCApi->impl_WebDownloadItem_ContentDisposition) {
        OHOS::WVLOG_E("WebDownloadItem_ContentDisposition not found.");
        return nullptr;
    }
    return g_nwebCApi->impl_WebDownloadItem_ContentDisposition(downloadItem);
}

extern "C" char *WebDownloadItem_ETag(const NWebDownloadItem *downloadItem)
{
    if (!g_nwebCApi->impl_WebDownloadItem_ETag) {
        OHOS::WVLOG_E("WebDownloadItem_ETag not found.");
        return nullptr;
    }
    return g_nwebCApi->impl_WebDownloadItem_ETag(downloadItem);
}

extern "C" char *WebDownloadItem_MimeType(const NWebDownloadItem *downloadItem)
{
    if (!g_nwebCApi->impl_WebDownloadItem_MimeType) {
        OHOS::WVLOG_E("WebDownloadItem_MimeType not found.");
        return nullptr;
    }
    return g_nwebCApi->impl_WebDownloadItem_MimeType(downloadItem);
}

extern "C" bool WebDownloadItem_IsPaused(const NWebDownloadItem *downloadItem)
{
    if (!g_nwebCApi->impl_WebDownloadItem_IsPaused) {
        OHOS::WVLOG_E("WebDownloadItem_IsPaused not found.");
        return false;
    }
    return g_nwebCApi->impl_WebDownloadItem_IsPaused(downloadItem);
}

extern "C" char *WebDownloadItem_Method(const NWebDownloadItem *downloadItem)
{
    if (!g_nwebCApi->impl_WebDownloadItem_Method) {
        OHOS::WVLOG_E("WebDownloadItem_Method not found.");
        return nullptr;
    }
    return g_nwebCApi->impl_WebDownloadItem_Method(downloadItem);
}

extern "C" int WebDownloadItem_LastErrorCode(const NWebDownloadItem *downloadItem)
{
    if (!g_nwebCApi->impl_WebDownloadItem_LastErrorCode) {
        OHOS::WVLOG_E("WebDownloadItem_LastErrorCode not found.");
        return 0;
    }
    return g_nwebCApi->impl_WebDownloadItem_LastErrorCode(downloadItem);
}

extern "C" char *WebDownloadItem_ReceivedSlices(const NWebDownloadItem *downloadItem)
{
    if (!g_nwebCApi->impl_WebDownloadItem_ReceivedSlices) {
        OHOS::WVLOG_E("WebDownloadItem_ReceivedSlices not found.");
        return nullptr;
    }
    return g_nwebCApi->impl_WebDownloadItem_ReceivedSlices(downloadItem);
}

extern "C" char *WebDownloadItem_LastModified(const NWebDownloadItem *downloadItem)
{
    if (!g_nwebCApi->impl_WebDownloadItem_LastModified) {
        OHOS::WVLOG_E("WebDownloadItem_LastModified not found.");
        return nullptr;
    }
    return g_nwebCApi->impl_WebDownloadItem_LastModified(downloadItem);
}

extern "C" int WebDownloadItem_NWebId(const NWebDownloadItem *downloadItem)
{
    if (!g_nwebCApi->impl_WebDownloadItem_NWebId) {
        OHOS::WVLOG_E("WebDownloadItem_NWebId not found.");
        return -1;
    }
    return g_nwebCApi->impl_WebDownloadItem_NWebId(downloadItem);
}

extern "C" void WebDownloadItem_CreateWebDownloadItem(NWebDownloadItem **downloadItem)
{
    if (!g_nwebCApi->impl_WebDownloadItem_CreateWebDownloadItem) {
        OHOS::WVLOG_E("WebDownloadItem_CreateWebDownloadItem not found.");
        return;
    }
    g_nwebCApi->impl_WebDownloadItem_CreateWebDownloadItem(downloadItem);
}

extern "C" void WebDownloadItem_Destroy(NWebDownloadItem *downloadItem)
{
    if (!g_nwebCApi->impl_WebDownloadItem_Destroy) {
        OHOS::WVLOG_E("WebDownloadItem_Destroy not found.");
        return;
    }
    g_nwebCApi->impl_WebDownloadItem_Destroy(downloadItem);
}

extern "C" void DestroyBeforeDownloadCallbackWrapper(WebBeforeDownloadCallbackWrapper *wrapper)
{
    if (!g_nwebCApi->impl_DestroyBeforeDownloadCallbackWrapper) {
        OHOS::WVLOG_E("DestroyBeforeDownloadCallbackWrapper not found.");
        return;
    }
    g_nwebCApi->impl_DestroyBeforeDownloadCallbackWrapper(wrapper);
}

extern "C" void DestroyDownloadItemCallbackWrapper(WebDownloadItemCallbackWrapper *wrapper)
{
    if (!g_nwebCApi->impl_DestroyDownloadItemCallbackWrapper) {
        OHOS::WVLOG_E("DestroyDownloadItemCallbackWrapper not found.");
        return;
    }
    g_nwebCApi->impl_DestroyDownloadItemCallbackWrapper(wrapper);
}

extern "C" void WebDownloadItem_SetGuid(NWebDownloadItem *downloadItem, const char *guid)
{
    if (!g_nwebCApi->impl_WebDownloadItem_SetGuid) {
        OHOS::WVLOG_E("WebDownloadItem_SetGuid not found.");
        return;
    }
    g_nwebCApi->impl_WebDownloadItem_SetGuid(downloadItem, guid);
}

extern "C" void WebDownloadItem_SetUrl(NWebDownloadItem *downloadItem, const char *url)
{
    if (!g_nwebCApi->impl_WebDownloadItem_SetUrl) {
        OHOS::WVLOG_E("WebDownloadItem_SetUrl not found.");
        return;
    }
    g_nwebCApi->impl_WebDownloadItem_SetUrl(downloadItem, url);
}

extern "C" void WebDownloadItem_SetFullPath(NWebDownloadItem *downloadItem, const char *full_path)
{
    if (!g_nwebCApi->impl_WebDownloadItem_SetFullPath) {
        OHOS::WVLOG_E("WebDownloadItem_SetFullPath not found.");
        return;
    }
    g_nwebCApi->impl_WebDownloadItem_SetFullPath(downloadItem, full_path);
}

extern "C" void WebDownloadItem_SetETag(NWebDownloadItem *downloadItem, const char *etag)
{
    if (!g_nwebCApi->impl_WebDownloadItem_SetETag) {
        OHOS::WVLOG_E("WebDownloadItem_SetETag not found.");
        return;
    }
    g_nwebCApi->impl_WebDownloadItem_SetETag(downloadItem, etag);
}

extern "C" void WebDownloadItem_SetLastModified(NWebDownloadItem *downloadItem, const char *lastModified)
{
    if (!g_nwebCApi->impl_WebDownloadItem_SetLastModified) {
        OHOS::WVLOG_E("WebDownloadItem_SetLastModified not found.");
        return;
    }
    g_nwebCApi->impl_WebDownloadItem_SetLastModified(downloadItem, lastModified);
}

extern "C" void WebDownloadItem_SetMimeType(NWebDownloadItem *downloadItem, const char *mimeType)
{
    if (!g_nwebCApi->impl_WebDownloadItem_SetMimeType) {
        OHOS::WVLOG_E("WebDownloadItem_SetMimeType not found.");
        return;
    }
    g_nwebCApi->impl_WebDownloadItem_SetMimeType(downloadItem, mimeType);
}

extern "C" void WebDownloadItem_SetReceivedBytes(NWebDownloadItem *downloadItem, int64_t receivedBytes)
{
    if (!g_nwebCApi->impl_WebDownloadItem_SetReceivedBytes) {
        OHOS::WVLOG_E("WebDownloadItem_SetReceivedBytes not found.");
        return;
    }
    g_nwebCApi->impl_WebDownloadItem_SetReceivedBytes(downloadItem, receivedBytes);
}

extern "C" void WebDownloadItem_SetTotalBytes(NWebDownloadItem *downloadItem, int64_t totalBytes)
{
    if (!g_nwebCApi->impl_WebDownloadItem_SetTotalBytes) {
        OHOS::WVLOG_E("WebDownloadItem_SetTotalBytes not found.");
        return;
    }
    g_nwebCApi->impl_WebDownloadItem_SetTotalBytes(downloadItem, totalBytes);
}

extern "C" void WebDownloadItem_SetReceivedSlices(NWebDownloadItem *downloadItem, const char *receivedSlices)
{
    if (!g_nwebCApi->impl_WebDownloadItem_SetReceivedSlices) {
        OHOS::WVLOG_E("WebDownloadItem_SetReceivedSlices not found.");
        return;
    }
    g_nwebCApi->impl_WebDownloadItem_SetReceivedSlices(downloadItem, receivedSlices);
}

namespace OHOS::NWeb {
bool NWebHelper::LoadNWebSDK()
{
    return ::LoadNWebSDK(libHandleWebEngine_);
}

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
    void *libHandleWebEngine = dlopen_ns(&dlns, LIB_NAME_WEB_ENGINE.c_str(), RTLD_NOW | RTLD_GLOBAL);
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
        delete[] buf;
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
        std::thread preReadThread([bundlePath]() { DoPreReadLib(bundlePath); });

        preReadThread.detach();
    }
}

bool NWebHelper::Init(bool from_ark)
{
    TryPreReadLibForFirstlyAppStartUp(bundlePath_);
    return LoadLib(from_ark);
}

using InitializeWebEngine = void (*)(const NWebInitArgs &);
bool NWebHelper::InitAndRun(bool from_ark)
{
    if (!Init(from_ark)) {
        return false;
    }

    WVLOG_I("InitializeWebEngine: load libs and initiallize cef.");
    if (libHandleWebEngine_ == nullptr) {
        WVLOG_E("InitializeWebEngine: libHandleWebEngine_ is nullptr");
        return false;
    }

    const std::string INITIALIZE_WEB_ENGINE_FUNC_NAME = "InitializeWebEngine";
    InitializeWebEngine initializeWebEngine =
        reinterpret_cast<InitializeWebEngine>(dlsym(libHandleWebEngine_, INITIALIZE_WEB_ENGINE_FUNC_NAME.c_str()));
    if (initializeWebEngine == nullptr) {
        WVLOG_E("initializeWebEngine: fail to dlsym %{public}s from libohoswebview.so",
            INITIALIZE_WEB_ENGINE_FUNC_NAME.c_str());
        return false;
    }

    OHOS::NWeb::NWebInitArgs initArgs;
    NWebAdapterHelper::Instance().ParseConfig(initArgs);
    // obtain bundle path
    std::shared_ptr<AbilityRuntime::ApplicationContext> ctx =
        AbilityRuntime::ApplicationContext::GetApplicationContext();
    if (!ctx) {
        WVLOG_E("Failed to init cef due to nil application context.");
        return false;
    }

    if (ctx->GetBaseDir().empty()) {
        WVLOG_E("Failed to init cef due to base dir is empty.");
        return false;
    }

    initArgs.web_engine_args_to_add.push_back(std::string("--user-data-dir=").append(ctx->GetBaseDir()));
    initArgs.web_engine_args_to_add.push_back(std::string("--bundle-installation-dir=").append(bundlePath_));

    initializeWebEngine(initArgs);
    return true;
}

void NWebHelper::SetBundlePath(const std::string &path)
{
    bundlePath_ = path;
}

NWebHelper::~NWebHelper()
{
    UnloadLib();
}

using CreateNWebFuncType = void (*)(const NWebCreateInfo &, std::shared_ptr<NWeb> &);
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
        WVLOG_I("GetCookieManager: init web engine start.");
        // obtain bundle path
        std::shared_ptr<AbilityRuntime::ApplicationContext> ctx =
            AbilityRuntime::ApplicationContext::GetApplicationContext();
        if (!ctx) {
            WVLOG_E("GetCookieManager: Failed to init web engine due to nil application context.");
            return nullptr;
        }
        // load so
        const std::string& bundle_path = ctx->GetBundleCodeDir();
        SetBundlePath(bundle_path);
        if (!Init(true)) {
            WVLOG_E("GetCookieManager: Failed to init web engine due to NWebHelper failure.");
            return nullptr;
        }
        WVLOG_I("GetCookieManager: init web engine success.");
    }
    if (libHandleWebEngine_ == nullptr) {
        WVLOG_E("GetCookieManager: libHandleWebEngine_ is nullptr");
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

using GetNWebFunc = void (*)(int32_t, std::weak_ptr<NWeb> &);
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

using SetWebDebuggingAccessFunc = void (*)(bool);
void NWebHelper::SetWebDebuggingAccess(bool isEnableDebug)
{
    if (libHandleWebEngine_ == nullptr) {
        WVLOG_E("libHandleWebEngine_ is nullptr");
        return;
    }
    
    const std::string SET_WEB_DEBUG_ACCESS_FUNC_NAME = "SetWebDebuggingAccess";
    SetWebDebuggingAccessFunc setWebDebuggingAccessFunc =
        reinterpret_cast<SetWebDebuggingAccessFunc>(dlsym(libHandleWebEngine_, SET_WEB_DEBUG_ACCESS_FUNC_NAME.c_str()));
    if (setWebDebuggingAccessFunc == nullptr) {
        WVLOG_E("doh: fail to dlsym %{public}s from libohoswebview.so", SET_WEB_DEBUG_ACCESS_FUNC_NAME.c_str());
        return;
    }
    setWebDebuggingAccessFunc(isEnableDebug);
    WVLOG_I("doh: success to dlysm %{public}s from libohoswebview.so", SET_WEB_DEBUG_ACCESS_FUNC_NAME.c_str());
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

using SetConnectionTimeoutFunc = void (*)(const int32_t&);
void NWebHelper::SetConnectionTimeout(const int32_t& timeout)
{
    if (libHandleWebEngine_ == nullptr) {
        WVLOG_E("libHandleNWebAdapter_ is nullptr");
        return;
    }

    const std::string SET_CONNECTION_TIMEOUT_FUNC_NAME = "SetConnectionTimeout";
    SetConnectionTimeoutFunc setConnectionTimeoutFunc =
        reinterpret_cast<SetConnectionTimeoutFunc>(dlsym(libHandleWebEngine_,
                                                         SET_CONNECTION_TIMEOUT_FUNC_NAME.c_str()));
    if (setConnectionTimeoutFunc == nullptr) {
        WVLOG_E("fail to dlsym %{public}s from libohoswebview.so", SET_CONNECTION_TIMEOUT_FUNC_NAME.c_str());
        return;
    }
    setConnectionTimeoutFunc(timeout);
    WVLOG_I("timeout value in NWebHelper: %{public}d", timeout);
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

std::shared_ptr<NWeb> NWebAdapterHelper::CreateNWeb(sptr<Surface> surface, const NWebInitArgs &initArgs, uint32_t width,
    uint32_t height)
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
    ParseConfig(createInfo.init_args);
    auto nweb = NWebHelper::Instance().CreateNWeb(createInfo);
    if (nweb == nullptr) {
        WVLOG_E("fail to create nweb instance");
    }
    return nweb;
}

std::shared_ptr<NWeb> NWebAdapterHelper::CreateNWeb(void *enhanceSurfaceInfo, const NWebInitArgs &initArgs,
    uint32_t width, uint32_t height)
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

std::string NWebAdapterHelper::GetConfigPath(const std::string &configFileName)
{
    char buf[PATH_MAX + 1];
    char *configPath = GetOneCfgFile(configFileName.c_str(), buf, PATH_MAX + 1);
    char tmpPath[PATH_MAX + 1] = { 0 };
    if (!configPath || strlen(configPath) == 0 || strlen(configPath) > PATH_MAX || !realpath(configPath, tmpPath)) {
        WVLOG_I("can not get customization config file");
        return "/system/" + configFileName;
    }
    return std::string(tmpPath);
}

std::unordered_map<std::string_view, std::function<std::string(std::string &)>> GetConfigMap()
{
    static std::unordered_map<std::string_view, std::function<std::string(std::string &)>> configMap = {
        { "renderConfig/renderProcessCount",
          [](std::string &contentStr) { return std::string("--renderer-process-limit=") + contentStr; } },
        { "mediaConfig/backgroundMediaShouldSuspend",
          [](std::string &contentStr) {
            return contentStr == "false" ? std::string("--disable-background-media-suspend") : std::string();
        } },
        { "loadurlSocPerfConfig/loadurlSocPerfParam",
          [](std::string &contentStr) {
            return contentStr == "true" ? std::string("--ohos-enable-loadurl-soc-perf") : std::string();
        } },
        { "mouseWheelSocPerfConfig/mouseWheelSocPerfParam",
          [](std::string &contentStr) {
            return contentStr == "true" ? std::string("--ohos-enable-mousewheel-soc-perf") : std::string();
        } },
        { "touchEventConfig/touchEventShouldRegister",
          [](std::string &contentStr) {
            return contentStr == "false" ? std::string("--disable-touch-event-register") : std::string();
        } }
    };
    return configMap;
}

void NWebAdapterHelper::ReadConfig(const xmlNodePtr &rootPtr, NWebInitArgs &init_args)
{
    auto configMap = GetConfigMap();
    for (xmlNodePtr curNodePtr = rootPtr->xmlChildrenNode; curNodePtr != nullptr; curNodePtr = curNodePtr->next) {
        if (curNodePtr->name == nullptr || curNodePtr->type == XML_COMMENT_NODE) {
            WVLOG_E("invalid node!");
            continue;
        }
        std::string nodeName = reinterpret_cast<const char *>(curNodePtr->name);
        for (xmlNodePtr curChildNodePtr = curNodePtr->xmlChildrenNode; curChildNodePtr != nullptr;
            curChildNodePtr = curChildNodePtr->next) {
            if (curChildNodePtr->name == nullptr || curChildNodePtr->type == XML_COMMENT_NODE) {
                WVLOG_E("invalid node!");
                continue;
            }
            std::string childNodeName = reinterpret_cast<const char *>(curChildNodePtr->name);
            xmlChar *content = xmlNodeGetContent(curChildNodePtr);
            if (content == nullptr) {
                WVLOG_E("read xml node error: nodeName:(%{public}s)", curChildNodePtr->name);
                continue;
            }
            std::string contentStr = reinterpret_cast<const char *>(content);
            xmlFree(content);
            auto it = configMap.find(nodeName + "/" + childNodeName);
            if (it == configMap.end()) {
                WVLOG_W("not found for web_config: %{public}s/%{public}s", nodeName.c_str(), childNodeName.c_str());
                continue;
            }
            std::string param = it->second(contentStr);
            if (!param.empty()) {
                init_args.web_engine_args_to_add.emplace_back(param);
            }
        }
    }
}

xmlNodePtr NWebAdapterHelper::GetChildrenNode(xmlNodePtr NodePtr, const std::string &childrenNodeName)
{
    WVLOG_D("GetChildrenNode:(%{public}s)", childrenNodeName.c_str());
    for (xmlNodePtr curNodePtr = NodePtr->xmlChildrenNode; curNodePtr != nullptr; curNodePtr = curNodePtr->next) {
        if (curNodePtr->name == nullptr || curNodePtr->type == XML_COMMENT_NODE) {
            WVLOG_E("invalid node!");
            continue;
        }
        if (!xmlStrcmp(curNodePtr->name, reinterpret_cast<const xmlChar*>(childrenNodeName.c_str()))) {
            return curNodePtr;
        }
    }
    return nullptr;
}

void NWebAdapterHelper::ParseConfig(NWebInitArgs &args)
{
    auto configFilePath = GetConfigPath(WEB_CONFIG_PATH);
    xmlDocPtr docPtr = xmlReadFile(configFilePath.c_str(), nullptr, XML_PARSE_NOBLANKS);
    if (docPtr == nullptr) {
        WVLOG_E("load xml error!");
        return;
    }

    xmlNodePtr rootPtr = xmlDocGetRootElement(docPtr);
    if (rootPtr == nullptr || rootPtr->name == nullptr ||
        xmlStrcmp(rootPtr->name, reinterpret_cast<const xmlChar *>("WEB"))) {
        WVLOG_E("get root element failed!");
        xmlFreeDoc(docPtr);
        return;
    }

    xmlNodePtr initNodePtr = GetChildrenNode(rootPtr, INIT_CONFIG);
    if (initNodePtr != nullptr) {
        WVLOG_D("read config from init node");
        ReadConfig(initNodePtr, args);
    } else {
        WVLOG_D("read config from root node");
        ReadConfig(rootPtr, args);
    }

    if (perfConfig_.empty()) {
        xmlNodePtr perfNodePtr = GetChildrenNode(rootPtr, PERFORMANCE_CONFIG);
        if (perfNodePtr != nullptr) {
            ParsePerfConfig(perfNodePtr);
        }
    }

    xmlFreeDoc(docPtr);
}

void NWebAdapterHelper::ParsePerfConfig(xmlNodePtr NodePtr)
{
    WVLOG_D("read performance config");
    for (xmlNodePtr curNodePtr = NodePtr->xmlChildrenNode; curNodePtr != nullptr; curNodePtr = curNodePtr->next) {
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
                WVLOG_E("read xml node error: nodeName:(%{public}s)", childNodeName.c_str());
                continue;
            }
            std::string contentStr = reinterpret_cast<const char*>(content);
            xmlFree(content);
            perfConfig_.emplace(nodeName + "/" + childNodeName, contentStr);
        }
    }
}

std::string NWebAdapterHelper::ParsePerfConfig(const std::string &configNodeName, const std::string &argsNodeName)
{
    auto it = perfConfig_.find(configNodeName + "/" + argsNodeName);
    if (it == perfConfig_.end()) {
        WVLOG_W("not found perf config for web_config: %{public}s/%{public}s", configNodeName.c_str(),
                argsNodeName.c_str());
        return "";
    }
    WVLOG_D("find performance config %{public}s/%{public}s, value is %{public}s.", configNodeName.c_str(),
        argsNodeName.c_str(), it->second.c_str());
    return it->second;
}
} // namespace OHOS::NWeb
