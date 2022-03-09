// Copyright (c) 2022 Huawei Device Co., Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "nweb_client_impl_test_for_intercept.h"

#include <fstream>
#include <cstring>
#include <string>
#include <sstream>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "nweb_test_log.h"
#include "nweb_url_resource_request.h"
#include "nweb_url_resource_response.h"
#include "utils.h"
#include "securec.h"

namespace OHOS::NWeb {
std::string g_data;
void NWebHandlerImplTestForIntercept::SetNWeb(std::shared_ptr<NWeb> nweb)
{
    nwebweak_ = nweb;
}

bool ReadFileToString(const char* path, std::string& data)
{
    TESTLOG_I(" ReadFileToString-1111%{public}s", path);
    // Implementation adapted from base/file_util.cc
    FILE* file = fopen(path, "rb");
    if (!file) {
        return false;
    }
    char buf[1 << 16];
    size_t len;
    while ((len = fread(buf, 1, sizeof(buf), file)) > 0) {
        data.append(buf, len);
    }
    fclose(file);
    return true;
}

bool GetResourceDir(std::string& dir)
{
    char buff[1024]; // 1024 size
    ssize_t len = readlink("/proc/self/exe", buff, sizeof(buff) - 1);
    if (len == -1) {
        return false;
    }

    buff[len] = 0;
    char* pos = strrchr(buff, '/');
    if (!pos) {
        return false;
    }

    if (strcpy_s(pos + 1, len, "files") != 0) {
        TESTLOG_I(" strcpy_s error");
        return false;
    }
    dir = std::string(buff);
    return true;
}

bool LoadBinaryResource(const char* resource_name, std::string& resource_data)
{
    std::string path;
    if (!GetResourceDir(path)) {
        return false;
    }
    path.append("/");
    path.append(resource_name);
    return ReadFileToString(path.c_str(), resource_data);
}

std::shared_ptr<NWebUrlResourceResponse> NWebHandlerImplTestForIntercept::OnHandleInterceptRequest(
    std::shared_ptr<NWebUrlResourceRequest> request)
{
    std::string url = request->Url();
    if (strstr(url.c_str(), ".png") != nullptr) {
        // system/bin/files
        LoadBinaryResource("2.png", g_data); // define 2.png name image
        std::shared_ptr<NWebUrlResourceResponse> response =
            std::make_shared<NWebUrlResourceResponse>("text/html", "UTF-8", g_data);
        return response;
    }
    return nullptr;
}
} // namespace OHOS::NWeb