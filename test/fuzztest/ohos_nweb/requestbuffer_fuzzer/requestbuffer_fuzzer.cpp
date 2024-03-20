/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "requestbuffer_fuzzer.h"

#include <cstring>
#include <securec.h>
#include <ui/rs_surface_node.h>

#include "nweb.h"
#include "nweb_adapter_helper.h"

#define private public
#include "nweb_surface_adapter.h"

using namespace OHOS::NWeb;
using namespace OHOS::Rosen;

namespace OHOS {
namespace {
sptr<Surface> g_surface = nullptr;
}

bool RequestBufferFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint32_t))) {
        return false;
    }

    auto surfaceAdapter = NWebSurfaceAdapter::Instance();
    uint32_t width;
    uint32_t height;
    if (memcpy_s(&width, sizeof(uint32_t), data, sizeof(uint32_t)) != 0) {
        return false;
    }
    if (memcpy_s(&height, sizeof(uint32_t), data, sizeof(uint32_t)) != 0) {
        return false;
    }
    if (!g_surface) {
        RSSurfaceNodeConfig config;
        config.SurfaceNodeName = "webTestSurfaceName";
        auto surfaceNode = RSSurfaceNode::Create(config, false);
        if (surfaceNode == nullptr) {
            return false;
        }
        g_surface = surfaceNode->GetSurface();
        if (g_surface== nullptr) {
            return false;
        }
    }
    surfaceAdapter.RequestBuffer(g_surface, width, height);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::RequestBufferFuzzTest(data, size);
    return 0;
}
