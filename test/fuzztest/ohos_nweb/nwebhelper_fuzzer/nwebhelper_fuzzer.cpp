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

#include <cstring>
#include <securec.h>
#include <ui/rs_surface_node.h>
#include <unordered_map>

#define private public
#include "foundation/ability/ability_runtime/interfaces/kits/native/appkit/ability_runtime/context/application_context.h"
#include "nweb.h"
#include "nweb_adapter_helper.h"
#include "nweb_c_api.h"
#include "nweb_create_window.h"
#include "nweb_helper.h"
#include "nweb_init_params.h"
#include "nweb_log.h"

using namespace OHOS;
using namespace OHOS::Rosen;
using namespace OHOS::AbilityRuntime;

namespace OHOS {
namespace {
sptr<Surface> g_surface = nullptr;
const int DEFAULT_WIDTH = 2560;
const int DEFAULT_HEIGHT = 1396;
const int32_t NWEB_MAX_WIDTH = 7681;
const std::string MOCK_INSTALLATION_DIR = "/data/app/el1/bundle/public/com.ohos.arkwebcore";
std::shared_ptr<AbilityRuntime::ApplicationContext> g_applicationContext = nullptr;
} // namespace

namespace AbilityRuntime {
std::shared_ptr<ApplicationContext> Context::GetApplicationContext()
{
    return g_applicationContext;
}
} // namespace AbilityRuntime

namespace NWeb {

std::unordered_map<std::string, std::string> g_argsMap;

bool NWebHelperFuzzTest(const uint8_t* data, size_t size)
{
    int32_t nweb_id = 1;
    bool result = NWebHelper::Instance().LoadNWebSDK();
    (void)result;
    NWebHelper::Instance().SetBundlePath(MOCK_INSTALLATION_DIR);
    result = NWebAdapterHelper::Instance().Init(false);
    (void)result;
    std::shared_ptr<NWebCreateInfoImpl> create_info = std::make_shared<NWebCreateInfoImpl>();
    std::shared_ptr<NWeb> nweb = NWebHelper::Instance().CreateNWeb(create_info);
    (void)nweb;
    std::shared_ptr<NWebDOHConfigImpl> config = std::make_shared<NWebDOHConfigImpl>();
    auto nwebHelper = NWebHelper::Instance().GetNWeb(nweb_id);
    (void)nwebHelper;
    NWebHelper::Instance().PrepareForPageLoad("web_test", true, 0);
    NWebHelper::Instance().WarmupServiceWorker("web_test");
    NWebHelper::Instance().PrefetchResource(nullptr, {}, "web_test", 0);
    NWebHelper::Instance().ClearPrefetchedResource({ "web_test" });
    NWebAdapterHelper::Instance().ReadConfigIfNeeded();
    result = NWebHelper::Instance().InitAndRun(false);
    (void)result;

    result = NWebHelper::Instance().InitAndRun(false);
    (void)result;
    NWebAdapterHelper::Instance().CreateNWeb(g_surface, GetInitArgs(), DEFAULT_WIDTH, DEFAULT_HEIGHT);
    result = NWebHelper::Instance().InitAndRun(false);
    (void)result;
    NWebAdapterHelper::Instance().CreateNWeb(g_surface, GetInitArgs(), DEFAULT_WIDTH, DEFAULT_HEIGHT);
    result = NWebHelper::Instance().LoadNWebSDK();
    (void)result;
    result = NWebHelper::Instance().LoadNWebSDK();
    (void)result;
    WebDownloadManager_PutDownloadCallback(nullptr);
    return true;
}

bool NWebHelperFuzzTest_002(const uint8_t* data, size_t size)
{
    auto web_storage = NWebHelper::Instance().GetWebStorage();
    bool result = false;
    if (web_storage != nullptr) {
        result = true;
    }
    (void)result;
    std::string config = NWebAdapterHelper::Instance().ParsePerfConfig("web", "test");
    (void)config;
    NWebConfigHelper::Instance().perfConfig_.emplace("web/test", "web_test");
    config = NWebAdapterHelper::Instance().ParsePerfConfig("web", "test");
    (void)config;
    return true;
}

bool NWebHelperFuzzTest_003(const uint8_t* data, size_t size)
{
    auto dataBase = NWebHelper::Instance().GetDataBase();
    bool result = false;
    if (dataBase != nullptr) {
        result = true;
    }
    (void)result;

    std::shared_ptr<NWebCookieManager> cook = NWebHelper::Instance().GetCookieManager();
    (void)cook;

    void* enhanceSurfaceInfo = nullptr;
    int32_t temp = 1;
    std::shared_ptr<NWeb> nweb =
        NWebAdapterHelper::Instance().CreateNWeb(enhanceSurfaceInfo, GetInitArgs(), DEFAULT_WIDTH, DEFAULT_HEIGHT);
    (void)nweb;
    enhanceSurfaceInfo = static_cast<void*>(&temp);
    nweb = NWebAdapterHelper::Instance().CreateNWeb(enhanceSurfaceInfo, GetInitArgs(), DEFAULT_WIDTH, DEFAULT_HEIGHT);
    (void)nweb;
    nweb = NWebAdapterHelper::Instance().CreateNWeb(enhanceSurfaceInfo, GetInitArgs(), DEFAULT_WIDTH, NWEB_MAX_WIDTH);
    (void)nweb;
    nweb = NWebAdapterHelper::Instance().CreateNWeb(enhanceSurfaceInfo, GetInitArgs(), NWEB_MAX_WIDTH, DEFAULT_HEIGHT);
    (void)nweb;
    std::shared_ptr<NWebCreateInfoImpl> create_info = std::make_shared<NWebCreateInfoImpl>();
    nweb = NWebHelper::Instance().CreateNWeb(create_info);
    (void)nweb;
    return true;
}

} // namespace NWeb
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::NWeb::NWebHelperFuzzTest(data, size);
    OHOS::NWeb::NWebHelperFuzzTest_002(data, size);
    OHOS::NWeb::NWebHelperFuzzTest_003(data, size);
    return 0;
}
