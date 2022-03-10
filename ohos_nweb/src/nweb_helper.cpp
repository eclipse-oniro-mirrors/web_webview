// Copyright (c) 2022 Huawei Device Co., Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "nweb_helper.h"

#include <iostream>
#include <thread>
#include <dlfcn.h>
#include "nweb_log.h"
#include "nweb_adapter_helper.h"
#include "nweb_window_adapter.h"
#include "nweb_surface_adapter.h"

namespace {
const uint32_t NWEB_SURFACE_MAX_WIDTH = 7680;
const uint32_t NWEB_SURFACE_MAX_HEIGHT = 7680;
}

namespace  OHOS::NWeb {
NWebHelper &NWebHelper::Instance()
{
    static NWebHelper helper;
    return helper;
}

bool NWebHelper::LoadLib()
{
    if (libHandleNWebAdapter_ != nullptr && libHandleWebEngine_ != nullptr) {
        return true;
    }
    const std::string LOAD_LIB_DIR = "/data/storage/el1/bundle/nweb/entry/libs/armeabi";
    const std::string LIB_PATH_NWEB_ADAPTER = LOAD_LIB_DIR + "/libnweb_adapter.so";
    const std::string LIB_PATH_WEB_ENGINE = LOAD_LIB_DIR + "/libweb_engine.so";
    void *libHandleWebEngine = ::dlopen(LIB_PATH_WEB_ENGINE.c_str(), RTLD_NOW);
    if (libHandleWebEngine == nullptr) {
        WVLOG_E("fail to dlopen %{public}s, errmsg=%{public}s", LIB_PATH_WEB_ENGINE.c_str(), dlerror());
        return false;
    }
    libHandleWebEngine_ = libHandleWebEngine;
    void *libHandleNWebAdapter = ::dlopen(LIB_PATH_NWEB_ADAPTER.c_str(), RTLD_NOW);
    if (libHandleNWebAdapter == nullptr) {
        WVLOG_E("fail to dlopen %{public}s, errmsg=%{public}s", LIB_PATH_NWEB_ADAPTER.c_str(), dlerror());
        return false;
    }
    libHandleNWebAdapter_ = libHandleNWebAdapter;
    return true;
}

void NWebHelper::UnloadLib()
{
    if (libHandleNWebAdapter_ != nullptr) {
        ::dlclose(libHandleNWebAdapter_);
        libHandleNWebAdapter_ = nullptr;
    }
    if (libHandleWebEngine_ != nullptr) {
        ::dlclose(libHandleWebEngine_);
        libHandleWebEngine_ = nullptr;
    }
}

bool NWebHelper::Init()
{
    return LoadLib();
}

NWebHelper::~NWebHelper()
{
    UnloadLib();
}

using CreateNWebFuncType = NWeb *(*)(const NWebCreateInfo &);
std::shared_ptr<NWeb> NWebHelper::CreateNWeb(const NWebCreateInfo &create_info)
{
    if (libHandleNWebAdapter_ == nullptr) {
        return nullptr;
    }

    const std::string CREATE_NWEB_FUNC_NAME = "CreateNWeb";
    CreateNWebFuncType funcCreateNWeb = 
        reinterpret_cast<CreateNWebFuncType>(dlsym(libHandleNWebAdapter_, CREATE_NWEB_FUNC_NAME.c_str()));
    if (funcCreateNWeb == nullptr) {
        WVLOG_E("fail to dlsym %{public}s from libohoswebview.so", CREATE_NWEB_FUNC_NAME.c_str());
        return nullptr;
    }

    std::shared_ptr<NWeb> nweb(funcCreateNWeb(create_info));
    if (nweb == nullptr) {
        WVLOG_E("fail to create nweb");
        return nullptr;
    }

    return nweb;
}

NWebAdapterHelper &NWebAdapterHelper::Instance()
{
    static NWebAdapterHelper helper;
    return helper;
}

bool NWebAdapterHelper::Init()
{
    return NWebHelper::Instance().Init();
}

std::shared_ptr<NWeb> NWebAdapterHelper::CreateNWeb(Rosen::Window *window, const NWebInitArgs &initArgs)
{
    if (window == nullptr) {
        WVLOG_E("fail to create nweb, input window is nullptr");
        return nullptr;
    }
    auto createInfo = NWebWindowAdapter::Instance().GetCreateInfo(window, initArgs);
    auto nweb = NWebHelper::Instance().CreateNWeb(createInfo);
    if (nweb == nullptr) {
        WVLOG_E("fail to create nweb instance");
        return nullptr;
    }
    NWebWindowAdapter::Instance().RegistEventCb(window, nweb);
    NWebWindowAdapter::Instance().RequestVsync(window, nweb);
    return nweb;
}

std::shared_ptr<NWeb> NWebAdapterHelper::CreateNWeb(sptr<Surface> surface,
                                                    const NWebInitArgs &initArgs,
                                                    uint32_t width,
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
    auto nweb = NWebHelper::Instance().CreateNWeb(createInfo);
    if (nweb == nullptr) {
        WVLOG_E("fail to create nweb instance");
    }
    return nweb;
}
} // namespace OHOS::NWeb
