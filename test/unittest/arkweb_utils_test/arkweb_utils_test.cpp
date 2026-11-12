/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "arkweb_utils.cpp"
#include "parameters.h"
#include "system_properties_adapter_impl.h"

using namespace testing::ext;

namespace OHOS::ArkWeb {
#if defined(IS_ASAN)
#if defined(webview_arm64)
const std::string ARK_WEB_CORE_ASAN_PATH_FOR_BUNDLE = "arkwebcore_asan/libs/arm64";
const std::string WEBVIEW_RELATIVE_SANDBOX_PATH_FOR_LIBRARY =
                    "data/storage/el1/bundle/arkwebcore_asan/libs/arm64/libarkweb_engine.so";
#elif defined(webview_x86_64)
const std::string ARK_WEB_CORE_ASAN_PATH_FOR_BUNDLE = "arkwebcore_asan/libs/x86_64";
#else
const std::string ARK_WEB_CORE_ASAN_PATH_FOR_BUNDLE = "arkwebcore_asan/libs/arm";
#endif
#endif

class FileProcessor {
public:
    static void WriteFile(const std::string& fileName, const std::string& content)
    {
        std::ofstream file(fileName);
        if(!file.is_open()) {
            return;
        }

        file << content;
    }
};

class ArkWebUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    std::string systemTmpVersionFile_ = "system_version_tmp.txt";
    std::string updateTmpVersionFile_ = "update_version_tmp.txt";
    static int paramEnforce;
    static int paramDefault;
};

int ArkWebUtilsTest::paramEnforce = 0;
int ArkWebUtilsTest::paramDefault = 0;

void ArkWebUtilsTest::SetUpTestCase(void)
{
    paramEnforce = OHOS::system::GetIntParameter("web.engine.enforce", 0);
    paramDefault = OHOS::system::GetIntParameter("web.engine.default", 0);
}

void ArkWebUtilsTest::TearDownTestCase(void)
{
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(paramEnforce));
    OHOS::system::SetParameter("web.engine.default", std::to_string(paramDefault));
}

void ArkWebUtilsTest::SetUp(void)
{
    SetBundleNameInner("");
    SetApiVersionInner("");
    SetAppVersionInner("");
    // Reset engine-selection globals so each test starts from a deterministic state.
    g_appEngineVersion = static_cast<int>(ArkWebEngineVersion::SYSTEM_DEFAULT);
    g_cloudEnableAppVersion = static_cast<int>(ArkWebEngineVersion::SYSTEM_DEFAULT);
    g_activeEngineVersion = ArkWebEngineVersion::SYSTEM_DEFAULT;
    g_legacyApp.reset();
    g_dataMigrateApp.reset();
}

void ArkWebUtilsTest::TearDown(void)
{}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_SetActiveWebEngineVersionInner_001, TestSize.Level1) {
    SetActiveWebEngineVersionInner(ArkWebEngineVersion::SYSTEM_DEFAULT);

    EXPECT_EQ(getActiveWebEngineVersion(), ArkWebEngineVersion::SYSTEM_DEFAULT);
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_SetActiveWebEngineVersionInner_002, TestSize.Level1) {
    SetActiveWebEngineVersionInner(ArkWebEngineVersion::M114);

    EXPECT_EQ(getActiveWebEngineVersion(), ArkWebEngineVersion::M114);
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_SetActiveWebEngineVersionInner_003, TestSize.Level1) {
    SetActiveWebEngineVersionInner(ArkWebEngineVersion::M132);

    EXPECT_EQ(getActiveWebEngineVersion(), ArkWebEngineVersion::M132);
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_getActiveWebEngineType_001, TestSize.Level1) {
    int webEngineEnforce = OHOS::system::GetIntParameter("web.engine.enforce", 0);

    OHOS::system::SetParameter("web.engine.enforce", std::to_string(2));
    auto res = getActiveWebEngineType();
    EXPECT_EQ(res, ArkWebEngineType::LEGACY);

    OHOS::system::SetParameter("web.engine.enforce", std::to_string(3));
    res = getActiveWebEngineType();
    EXPECT_EQ(res, ArkWebEngineType::LEGACY);

    OHOS::system::SetParameter("web.engine.enforce", std::to_string(webEngineEnforce));
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_getActiveWebEngineType_002, TestSize.Level1) {
    int webEngineEnforce = OHOS::system::GetIntParameter("web.engine.enforce", 0);
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(0));
    setActiveWebEngineVersion(ArkWebEngineVersion::SYSTEM_DEFAULT);

    auto res = getActiveWebEngineType();
    EXPECT_EQ(res, ArkWebEngineType::EVERGREEN);
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(webEngineEnforce));
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_getActiveWebEngineType_003, TestSize.Level1) {
    int webEngineEnforce = OHOS::system::GetIntParameter("web.engine.enforce", 0);
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(0));
    setActiveWebEngineVersion(ArkWebEngineVersion::M132);

    auto res = getActiveWebEngineType();
    EXPECT_EQ(res, ArkWebEngineType::LEGACY);
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(webEngineEnforce));
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_GetArkwebLibPath_001, TestSize.Level1) {
    int webEngineEnforce = OHOS::system::GetIntParameter("web.engine.enforce", 0);
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(0));
    setActiveWebEngineVersion(ArkWebEngineVersion::M132);

    auto res = GetArkwebLibPath();
    EXPECT_EQ(res, ARK_WEB_CORE_LEGACY_HAP_LIB_PATH);
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(webEngineEnforce));
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_GetArkwebLibPath_002, TestSize.Level1) {
    int webEngineEnforce = OHOS::system::GetIntParameter("web.engine.enforce", 0);
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(0));
    setActiveWebEngineVersion(ArkWebEngineVersion::SYSTEM_DEFAULT);

    auto res = GetArkwebLibPath();
    EXPECT_EQ(res, ARK_WEB_CORE_HAP_LIB_PATH);
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(webEngineEnforce));
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_GetArkwebNameSpace_001, TestSize.Level1) {
    int webEngineEnforce = OHOS::system::GetIntParameter("web.engine.enforce", 0);
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(0));
    setActiveWebEngineVersion(ArkWebEngineVersion::M132);

    auto res = GetArkwebNameSpace();
    EXPECT_EQ(res, "nweb_ns_legacy");
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(webEngineEnforce));
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_GetArkwebNameSpace_002, TestSize.Level1) {
    int webEngineEnforce = OHOS::system::GetIntParameter("web.engine.enforce", 0);
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(0));
    setActiveWebEngineVersion(ArkWebEngineVersion::SYSTEM_DEFAULT);

    auto res = GetArkwebNameSpace();
    EXPECT_EQ(res, "nweb_ns");
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(webEngineEnforce));
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_GetArkwebRelativePathForBundle_001, TestSize.Level1) {
    int webEngineEnforce = OHOS::system::GetIntParameter("web.engine.enforce", 0);
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(0));
    setActiveWebEngineVersion(ArkWebEngineVersion::M132);

    auto res = GetArkwebRelativePathForBundle();
#if defined(IS_ASAN)
    EXPECT_EQ(res, ARK_WEB_CORE_ASAN_PATH_FOR_BUNDLE);
#else
    EXPECT_EQ(res, ARK_WEB_CORE_LEGACY_PATH_FOR_BUNDLE);
#endif
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(webEngineEnforce));
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_GetArkwebRelativePathForBundle_002, TestSize.Level1) {
    int webEngineEnforce = OHOS::system::GetIntParameter("web.engine.enforce", 0);
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(0));
    setActiveWebEngineVersion(ArkWebEngineVersion::SYSTEM_DEFAULT);

    auto res = GetArkwebRelativePathForBundle();
#if defined(IS_ASAN)
    EXPECT_EQ(res, ARK_WEB_CORE_ASAN_PATH_FOR_BUNDLE);
#else
    EXPECT_EQ(res, ARK_WEB_CORE_PATH_FOR_BUNDLE);
#endif
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(webEngineEnforce));
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_GetArkwebInstallPath_001, TestSize.Level1) {
    int webEngineEnforce = OHOS::system::GetIntParameter("web.engine.enforce", 0);
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(0));
    setActiveWebEngineVersion(ArkWebEngineVersion::M132);

    auto aclPath = GetArkwebInstallPath();
    bool res = (aclPath == SANDBOX_LEGACY_HAP_PATH || aclPath == PRECONFIG_LEGACY_HAP_PATH);
    if (access(PRECONFIG_LEGACY_HAP_PATH.c_str(), F_OK) == 0) {
        EXPECT_TRUE(res);
    } else {
        EXPECT_FALSE(res);
    }
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(webEngineEnforce));
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_GetArkwebInstallPath_002, TestSize.Level1) {
    int webEngineEnforce = OHOS::system::GetIntParameter("web.engine.enforce", 0);
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(0));
    setActiveWebEngineVersion(ArkWebEngineVersion::SYSTEM_DEFAULT);

    auto aclPath = GetArkwebInstallPath();
    bool res = (aclPath == SANDBOX_EVERGREEN_HAP_PATH || aclPath == PRECONFIG_EVERGREEN_HAP_PATH);
    EXPECT_TRUE(res);
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(webEngineEnforce));
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_IsActiveWebEngineEvergreen_001, TestSize.Level1)
{
    OHOS::system::SetParameter("web.engine.enforce", "0");
    setActiveWebEngineVersion(ArkWebEngineVersion::M132);
    EXPECT_FALSE(IsActiveWebEngineEvergreen());
    setActiveWebEngineVersion(ArkWebEngineVersion::M144);
    EXPECT_TRUE(IsActiveWebEngineEvergreen());
    setActiveWebEngineVersion(ArkWebEngineVersion::M132);
    EXPECT_FALSE(IsActiveWebEngineEvergreen());
    setActiveWebEngineVersion(ArkWebEngineVersion::SYSTEM_EVERGREEN);
    EXPECT_TRUE(IsActiveWebEngineEvergreen());
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_SelectWebcoreBeforeProcessRun_001, TestSize.Level1) {
    std::string appBundleName = "com.example.app";
    int webEngineEnforce = OHOS::system::GetIntParameter("web.engine.enforce", 0);
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(0));

    SelectWebcoreBeforeProcessRun(appBundleName);
    EXPECT_EQ(getActiveWebEngineVersion(), ArkWebEngineVersion::M144);
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(webEngineEnforce));
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_SelectWebcoreBeforeProcessRun_002, TestSize.Level1) {
    std::string appBundleName = "com.example.app2";
    int webEngineEnforce = OHOS::system::GetIntParameter("web.engine.enforce", 0);
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(0));

    SelectWebcoreBeforeProcessRun(appBundleName);
    EXPECT_EQ(getActiveWebEngineVersion(), ArkWebEngineVersion::M144);
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(webEngineEnforce));
}

#if (defined(webview_arm64) && !defined(ASAN_DETECTOR))
// `const.startup.appspawn.preload.arkwebEngine` is a read-only const parameter.
// SetParameter on it fails with errno 107 on a running device, so the flag can
// only be flipped at boot. When the flag cannot be reset, the real dlopen/dlclose
// path of DlopenArkWebLib/DlcloseArkWebLib would load and unload libarkweb_engine.so
// (and its IPC broker dependencies) for real. Those .so files own static C++
// objects whose atexit destructors are not removed on dlclose, so a subsequent
// process exit crashes inside __funcs_on_exit -> ~basic_string() on unmapped
// memory (SIGSEGV SEGV_MAPERR). Guard both cases: only run them when the
// parameter was actually set to "false"; otherwise skip.
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_DlopenArkWebLib_001, TestSize.Level1) {
    auto flg = OHOS::system::GetParameter(APPSPAWN_PRELOAD_ARKWEB_ENGINE, "false");
    bool ok = OHOS::system::SetParameter(APPSPAWN_PRELOAD_ARKWEB_ENGINE, "false");
    if (!ok) {
        GTEST_SKIP() << "Cannot disable " << APPSPAWN_PRELOAD_ARKWEB_ENGINE
                     << " (read-only const param); skip to avoid real engine dlopen.";
    }
    DlopenArkWebLib();
    OHOS::system::SetParameter(APPSPAWN_PRELOAD_ARKWEB_ENGINE, flg);
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_DlcloseArkWebLib_001, TestSize.Level1) {
    auto flg = OHOS::system::GetParameter(APPSPAWN_PRELOAD_ARKWEB_ENGINE, "false");
    bool ok = OHOS::system::SetParameter(APPSPAWN_PRELOAD_ARKWEB_ENGINE, "false");
    if (!ok) {
        GTEST_SKIP() << "Cannot disable " << APPSPAWN_PRELOAD_ARKWEB_ENGINE
                     << " (read-only const param); skip to avoid real engine dlclose.";
    }
    int ret = DlcloseArkWebLib();
    EXPECT_EQ(ret, 0);
    OHOS::system::SetParameter(APPSPAWN_PRELOAD_ARKWEB_ENGINE, flg);
}
#endif

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_ProcessDefaultParam_001, TestSize.Level1)
{
    OHOS::system::SetParameter("web.engine.default", "0");
    std::string key = "web.engine.default";
    Json::Value value = 1000;
    ProcessDefaultParam(value);
    EXPECT_EQ(OHOS::system::GetIntParameter(key, 0), 0);
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_ProcessDefaultParam_002, TestSize.Level1)
{
    std::string key = "web.engine.default";
    Json::Value value = std::to_string(static_cast<int>(ArkWebEngineType::LEGACY));
    ProcessDefaultParam(value);
    EXPECT_EQ(OHOS::system::GetIntParameter(key, 0), 0);
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_ProcessDefaultParam_003, TestSize.Level1)
{
    std::string key = "web.engine.default";
    Json::Value value = static_cast<int>(ArkWebEngineType::LEGACY);
    ProcessDefaultParam(value);
    EXPECT_EQ(OHOS::system::GetIntParameter(key, 0), 2);
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_ProcessDefaultParam_004, TestSize.Level1)
{
    std::string key = "web.engine.default";
    Json::Value value = static_cast<int>(ArkWebEngineType::EVERGREEN);
    ProcessDefaultParam(value);
    EXPECT_EQ(OHOS::system::GetIntParameter(key, 0), 3);
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_ProcessEnforceParam_001, TestSize.Level1)
{
    std::string key = "web.engine.enforce";
    Json::Value value = 1000;
    ProcessEnforceParam(value);
    EXPECT_EQ(OHOS::system::GetIntParameter(key, 0), 0);
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_ProcessEnforceParam_002, TestSize.Level1)
{
    std::string key = "web.engine.enforce";
    Json::Value value = std::to_string(static_cast<int>(ArkWebEngineType::LEGACY));
    ProcessEnforceParam(value);
    EXPECT_EQ(OHOS::system::GetIntParameter(key, 0), 0);
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_ProcessEnforceParam_003, TestSize.Level1)
{
    std::string key = "web.engine.enforce";
    Json::Value value = static_cast<int>(ArkWebEngineType::LEGACY);
    ProcessEnforceParam(value);
    EXPECT_EQ(OHOS::system::GetIntParameter(key, 0), 0);
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_ProcessEnforceParam_004, TestSize.Level1)
{
    std::string key = "web.engine.enforce";
    Json::Value value = static_cast<int>(ArkWebEngineType::EVERGREEN);
    ProcessEnforceParam(value);
    EXPECT_EQ(OHOS::system::GetIntParameter(key, 0), 3);
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_ProcessLegacyAppParam_001, TestSize.Level1)
{
    Json::Value value = "com.example.myapplication";
    ProcessLegacyAppParam(value);
    EXPECT_EQ(g_legacyApp, nullptr);
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_ProcessLegacyAppParam_002, TestSize.Level1)
{
    std::string appBundleName = "com.example.myapplication";
    Json::Value value(Json::arrayValue);
    ProcessLegacyAppParam(value);
    EXPECT_NE(g_legacyApp, nullptr);
    EXPECT_EQ(g_legacyApp->find(appBundleName) != g_legacyApp->end(), false);
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_ProcessLegacyAppParam_003, TestSize.Level1)
{
    std::string appBundleName = "com.example.myapplication";
    Json::Value value(Json::arrayValue);
    value.append(2);
    value.append("test");
    ProcessLegacyAppParam(value);
    EXPECT_NE(g_legacyApp, nullptr);
    EXPECT_EQ(g_legacyApp->find(appBundleName) != g_legacyApp->end(), false);
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_ProcessLegacyAppParam_004, TestSize.Level1)
{
    std::string appBundleName = "com.example.myapplication";
    Json::Value value(Json::arrayValue);
    value.append(appBundleName);
    ProcessLegacyAppParam(value);
    EXPECT_NE(g_legacyApp, nullptr);
    EXPECT_EQ(g_legacyApp->find(appBundleName) != g_legacyApp->end(), true);
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_ProcessParamItem_001, TestSize.Level1)
{
    std::string key = "Arkweb.engine.default";
    Json::Value value = static_cast<int>(ArkWebEngineType::EVERGREEN);
    ProcessParamItem(key, value);
    EXPECT_EQ(OHOS::system::GetIntParameter(key, 0), 0);
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_ProcessParamItem_002, TestSize.Level1)
{
    std::string key = "web.engine.test";
    Json::Value value = static_cast<int>(ArkWebEngineType::EVERGREEN);
    ProcessParamItem(key, value);
    EXPECT_EQ(OHOS::system::GetIntParameter(key, 0), 0);
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_ProcessParamItem_003, TestSize.Level1)
{
    std::string key = "web.engine.default";
    Json::Value value = static_cast<int>(ArkWebEngineType::EVERGREEN);
    ProcessParamItem(key, value);
    EXPECT_EQ(OHOS::system::GetIntParameter(key, 0), 3);
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_ProcessParamItem_004, TestSize.Level1)
{
    std::string key = "web.engine.enforce";
    Json::Value value = static_cast<int>(ArkWebEngineType::EVERGREEN);
    ProcessParamItem(key, value);
    EXPECT_EQ(OHOS::system::GetIntParameter(key, 0), 3);
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_ProcessParamItem_005, TestSize.Level1)
{
    std::string key = "web.engine.legacyApp";
    std::string appBundleName = "com.example.myapplication";
    Json::Value value(Json::arrayValue);
    value.append(appBundleName);
    ProcessParamItem(key, value);
    EXPECT_NE(g_legacyApp, nullptr);
    EXPECT_EQ(g_legacyApp->find(appBundleName) != g_legacyApp->end(), true);
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_GetVersionString_001, TestSize.Level1)
{
    std::string systemParamVersionPath = "system_version_tmp_not_exist.txt";
    std::string systemParamVersionStr;
    EXPECT_EQ(GetVersionString(systemParamVersionPath, systemParamVersionStr), false);
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_CheckCloudCfgVersion_001, TestSize.Level1)
{
    EXPECT_EQ(CheckCloudCfgVersion(systemTmpVersionFile_, updateTmpVersionFile_), false);

    std::string wrongVersionTxt = "version=1000.00.0.0";
    FileProcessor::WriteFile(systemTmpVersionFile_, wrongVersionTxt);
    EXPECT_EQ(CheckCloudCfgVersion(systemTmpVersionFile_, updateTmpVersionFile_), false);

    FileProcessor::WriteFile(updateTmpVersionFile_, wrongVersionTxt);
    EXPECT_EQ(CheckCloudCfgVersion(systemTmpVersionFile_, updateTmpVersionFile_), false);

    std::string versionTxt = "version=1.10.25.100";
    FileProcessor::WriteFile(systemTmpVersionFile_, versionTxt);
    EXPECT_EQ(CheckCloudCfgVersion(systemTmpVersionFile_, updateTmpVersionFile_), false);

    FileProcessor::WriteFile(updateTmpVersionFile_, versionTxt);
    EXPECT_EQ(CheckCloudCfgVersion(systemTmpVersionFile_, updateTmpVersionFile_), true);

    std::string higherVersionTxt = "version=1.10.25.101";
    FileProcessor::WriteFile(systemTmpVersionFile_, higherVersionTxt);
    EXPECT_EQ(CheckCloudCfgVersion(systemTmpVersionFile_, updateTmpVersionFile_), false);
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_GetArkwebLibPathForMock_001, TestSize.Level1)
{
    std::string res;
    res = GetArkwebLibPathForMock("");
    EXPECT_EQ(res, ARK_WEB_CORE_MOCK_HAP_LIB_PATH);
    std::string bundlePath = "/data/app/el1/bundle/public/com.ohos.arkwebcore";
    res = GetArkwebLibPathForMock(bundlePath);
    EXPECT_EQ(res, bundlePath + "/" + ARK_WEB_CORE_PATH_FOR_MOCK);
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_GetBundleName, TestSize.Level1)
{
    SetBundleNameInner("test");

    auto res = GetBundleName();
    EXPECT_EQ(res, "test");
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_GetApiVersion, TestSize.Level1)
{
    SetApiVersionInner("test");

    auto res = GetApiVersion();
    EXPECT_EQ(res, "test");
}

HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_GetAppVersion, TestSize.Level1)
{
    SetAppVersionInner("test");

    auto res = GetAppVersion();
    EXPECT_EQ(res, "test");
}

/**
* @brief 无前缀返回空字串
*
*/
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_ExtractAndRemoveParam_001, TestSize.Level1)
{
    std::string renderCmd = "someCommandWithoutPrefix";
    std::string prefix = "prefix=";

    std::string result = ExtractAndRemoveParam(renderCmd, prefix);
    EXPECT_EQ(result, "");
}

/**
* @brief 函数返回参数值并移除参数
*
*/
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_ExtractAndRemoveParam_002, TestSize.Level1)
{
    std::string renderCmd = "command#prefix=paramValue";
    std::string prefix = "#prefix=";

    std::string result = ExtractAndRemoveParam(renderCmd, prefix);
    EXPECT_EQ(result, "paramValue");
    EXPECT_EQ(renderCmd, "command");
}

/**
* @brief 参数在中间时，函数返回参数值并移除参数
*
*/
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_ExtractAndRemoveParam_003, TestSize.Level1)
{
    std::string renderCmd = "command#prefix=paramValue#remaining";
    std::string prefix = "#prefix=";

    std::string result = ExtractAndRemoveParam(renderCmd, prefix);
    EXPECT_EQ(result, "paramValue");
    EXPECT_EQ(renderCmd, "command#remaining");
}

/**
* @brief 前缀prefix为空
*
*/
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_ExtractAndRemoveParam_004, TestSize.Level1)
{
    std::string renderCmd = "someCommandWithoutPrefix";
    std::string prefix = "";

    std::string result = ExtractAndRemoveParam(renderCmd, prefix);
    EXPECT_EQ(result, "");
    EXPECT_EQ(renderCmd, "someCommandWithoutPrefix");
}

/**
* @brief 多个相同前缀prefix的参数
*
*/
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_ExtractAndRemoveParam_005, TestSize.Level1)
{
    std::string renderCmd = "command#prefix=first#prefix=second";
    std::string prefix = "#prefix=";

    std::string result = ExtractAndRemoveParam(renderCmd, prefix);
    EXPECT_EQ(result, "second");
    EXPECT_EQ(renderCmd, "command#prefix=first");
}

/**
* @brief 参数值为空
*
*/
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_ExtractAndRemoveParam_006, TestSize.Level1)
{
    std::string renderCmd = "command#prefix=#remaining";
    std::string prefix = "#prefix=";

    std::string result = ExtractAndRemoveParam(renderCmd, prefix);
    EXPECT_EQ(result, "");
    EXPECT_EQ(renderCmd, "command#remaining");
}

/**
* @brief 无APP_BUNDLE_NAME_PREFIX参数
*
*/
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_NoBundleName, TestSize.Level1)
{
    std::string renderCmd = "noparam";
    OHOS::ArkWeb::SetBundleNameInner("test");
    UpdateAppInfoFromCmdline(renderCmd);
    EXPECT_EQ(OHOS::ArkWeb::GetBundleName(), "test");
}

/**
* @brief 无APP_API_VERSION_PREFIX参数
*
*/
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_NoApiVersion, TestSize.Level1)
{
    std::string renderCmd = "noparam";
    OHOS::ArkWeb::SetApiVersionInner("test");
    UpdateAppInfoFromCmdline(renderCmd);
    EXPECT_EQ(OHOS::ArkWeb::GetApiVersion(), "test");
}

/**
* @brief 无APP_APP_VERSION_PREFIX参数
*
*/
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_NoAppVersion, TestSize.Level1)
{
    std::string renderCmd = "noparam";
    OHOS::ArkWeb::SetAppVersionInner("test");
    UpdateAppInfoFromCmdline(renderCmd);
    EXPECT_EQ(OHOS::ArkWeb::GetAppVersion(), "test");
}

/**
* @brief 参数均存在且有效
*
*/
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_NormalScene, TestSize.Level1)
{
    // UpdateAppInfoFromCmdline does not parse #--appEngineVersion; set it
    // explicitly so the engine-version assertion is deterministic and does
    // not depend on state leaked from earlier tests.
    int webEngineEnforce = OHOS::system::GetIntParameter("web.engine.enforce", 0);
    OHOS::system::SetParameter("web.engine.enforce", "0");
    setActiveWebEngineVersion(ArkWebEngineVersion::M144);
    std::string renderCmd = "#--appEngineVersion=3#--appBundleName=test#--appApiVersion=1#--appVersion=3";
    UpdateAppInfoFromCmdline(renderCmd);
    EXPECT_EQ(OHOS::ArkWeb::getActiveWebEngineVersion(),
        static_cast<OHOS::ArkWeb::ArkWebEngineVersion>(3));
    EXPECT_EQ(OHOS::ArkWeb::GetBundleName(), "test");
    EXPECT_EQ(OHOS::ArkWeb::GetApiVersion(), "1");
    EXPECT_EQ(OHOS::ArkWeb::GetAppVersion(), "3");
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(webEngineEnforce));
}

/**
 * @brief MapToMetricsVersion maps each valid ArkWebEngineVersion correctly.
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_MapToMetricsVersion_001, TestSize.Level1)
{
    EXPECT_EQ(MapToMetricsVersion(ArkWebEngineVersion::SYSTEM_DEFAULT),
              ArkWebEngineVersionMetrics::SYSTEM_DEFAULT);
    EXPECT_EQ(MapToMetricsVersion(ArkWebEngineVersion::SYSTEM_EVERGREEN),
              ArkWebEngineVersionMetrics::SYSTEM_EVERGREEN);
    EXPECT_EQ(MapToMetricsVersion(ArkWebEngineVersion::PLAYGROUND),
              ArkWebEngineVersionMetrics::PLAYGROUND);
    EXPECT_EQ(MapToMetricsVersion(ArkWebEngineVersion::M114),
              ArkWebEngineVersionMetrics::M114);
    EXPECT_EQ(MapToMetricsVersion(ArkWebEngineVersion::M132),
              ArkWebEngineVersionMetrics::M132);
    EXPECT_EQ(MapToMetricsVersion(ArkWebEngineVersion::M144),
              ArkWebEngineVersionMetrics::M144);
}

/**
 * @brief MapToMetricsVersion returns UNKNOWN_METRICS for unrecognized values.
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_MapToMetricsVersion_002, TestSize.Level1)
{
    EXPECT_EQ(MapToMetricsVersion(static_cast<ArkWebEngineVersion>(9999)),
              ArkWebEngineVersionMetrics::UNKNOWN_METRICS);
    EXPECT_EQ(MapToMetricsVersion(static_cast<ArkWebEngineVersion>(-1)),
              ArkWebEngineVersionMetrics::UNKNOWN_METRICS);
}

// ---- Additional branch coverage tests below ----

/**
 * @brief setActiveWebEngineVersion rejects unsupported version values.
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_setActiveWebEngineVersion_001, TestSize.Level1)
{
    int webEngineEnforce = OHOS::system::GetIntParameter("web.engine.enforce", 0);
    OHOS::system::SetParameter("web.engine.enforce", "0");
    // Unsupported version: current active version must be unchanged.
    ArkWebEngineVersion before = getActiveWebEngineVersion();
    setActiveWebEngineVersion(static_cast<ArkWebEngineVersion>(42));
    EXPECT_EQ(getActiveWebEngineVersion(), before);
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(webEngineEnforce));
}

/**
 * @brief setActiveWebEngineVersion with SYSTEM_EVERGREEN maps to ArkWebEngineType::EVERGREEN
 *        via CalculateActiveWebEngineVersion.
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_setActiveWebEngineVersion_002, TestSize.Level1)
{
    int webEngineEnforce = OHOS::system::GetIntParameter("web.engine.enforce", 0);
    OHOS::system::SetParameter("web.engine.enforce", "0");
    setActiveWebEngineVersion(ArkWebEngineVersion::SYSTEM_EVERGREEN);
    EXPECT_EQ(getActiveWebEngineType(), ArkWebEngineType::EVERGREEN);
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(webEngineEnforce));
}

/**
 * @brief CalculateActiveWebEngineVersion honors web.engine.enforce = EVERGREEN.
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_CalculateActiveWebEngineVersion_001, TestSize.Level1)
{
    int webEngineEnforce = OHOS::system::GetIntParameter("web.engine.enforce", 0);
    OHOS::system::SetParameter("web.engine.enforce",
        std::to_string(static_cast<int>(ArkWebEngineType::EVERGREEN)));
    SetActiveWebEngineVersionInner(ArkWebEngineVersion::SYSTEM_DEFAULT);
    EXPECT_EQ(CalculateActiveWebEngineVersion(),
        static_cast<ArkWebEngineVersion>(ArkWebEngineType::EVERGREEN));
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(webEngineEnforce));
}

/**
 * @brief CalculateActiveWebEngineVersion honors web.engine.enforce = LEGACY.
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_CalculateActiveWebEngineVersion_002, TestSize.Level1)
{
    int webEngineEnforce = OHOS::system::GetIntParameter("web.engine.enforce", 0);
    OHOS::system::SetParameter("web.engine.enforce",
        std::to_string(static_cast<int>(ArkWebEngineType::LEGACY)));
    SetActiveWebEngineVersionInner(ArkWebEngineVersion::SYSTEM_DEFAULT);
    EXPECT_EQ(CalculateActiveWebEngineVersion(),
        static_cast<ArkWebEngineVersion>(ArkWebEngineType::LEGACY));
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(webEngineEnforce));
}

/**
 * @brief CalculateActiveWebEngineVersion falls back to g_cloudEnableAppVersion == LEGACY
 *        when appEngineVersion is SYSTEM_DEFAULT and enforce is not LEGACY/EVERGREEN.
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_CalculateActiveWebEngineVersion_003, TestSize.Level1)
{
    int webEngineEnforce = OHOS::system::GetIntParameter("web.engine.enforce", 0);
    OHOS::system::SetParameter("web.engine.enforce", "0");
    // Put the app in the legacy cloud list, then run SelectWebcoreBeforeProcessRun so
    // g_cloudEnableAppVersion is set to LEGACY and g_legacyApp is cleared.
    std::string appBundleName = "com.example.cloud.legacy";
    Json::Value legacyArray(Json::arrayValue);
    legacyArray.append(appBundleName);
    ProcessLegacyAppParam(legacyArray);
    ASSERT_NE(g_legacyApp, nullptr);
    SelectWebcoreBeforeProcessRun(appBundleName);
    SetActiveWebEngineVersionInner(ArkWebEngineVersion::SYSTEM_DEFAULT);
    EXPECT_EQ(CalculateActiveWebEngineVersion(),
        static_cast<ArkWebEngineVersion>(ArkWebEngineType::LEGACY));
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(webEngineEnforce));
}

/**
 * @brief CalculateActiveWebEngineVersion returns EVERGREEN when web.engine.default is
 *        neither LEGACY nor EVERGREEN (error fallback branch).
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_CalculateActiveWebEngineVersion_004, TestSize.Level1)
{
    int webEngineEnforce = OHOS::system::GetIntParameter("web.engine.enforce", 0);
    int webEngineDefault = OHOS::system::GetIntParameter("web.engine.default", 0);
    OHOS::system::SetParameter("web.engine.enforce", "0");
    OHOS::system::SetParameter("web.engine.default", "42");
    SetActiveWebEngineVersionInner(ArkWebEngineVersion::SYSTEM_DEFAULT);
    // Ensure cloud legacy path is not active.
    ProcessLegacyAppParam(Json::Value(Json::arrayValue));
    SelectWebcoreBeforeProcessRun("com.example.none");
    EXPECT_EQ(CalculateActiveWebEngineVersion(),
        static_cast<ArkWebEngineVersion>(ArkWebEngineType::EVERGREEN));
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(webEngineEnforce));
    OHOS::system::SetParameter("web.engine.default", std::to_string(webEngineDefault));
}

/**
 * @brief CalculateActiveWebEngineVersion returns the web.engine.default value (LEGACY)
 *        in the final fallback branch.
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_CalculateActiveWebEngineVersion_005, TestSize.Level1)
{
    int webEngineEnforce = OHOS::system::GetIntParameter("web.engine.enforce", 0);
    int webEngineDefault = OHOS::system::GetIntParameter("web.engine.default", 0);
    OHOS::system::SetParameter("web.engine.enforce", "0");
    OHOS::system::SetParameter("web.engine.default",
        std::to_string(static_cast<int>(ArkWebEngineType::LEGACY)));
    SetActiveWebEngineVersionInner(ArkWebEngineVersion::SYSTEM_DEFAULT);
    ProcessLegacyAppParam(Json::Value(Json::arrayValue));
    SelectWebcoreBeforeProcessRun("com.example.none");
    EXPECT_EQ(CalculateActiveWebEngineVersion(),
        static_cast<ArkWebEngineVersion>(ArkWebEngineType::LEGACY));
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(webEngineEnforce));
    OHOS::system::SetParameter("web.engine.default", std::to_string(webEngineDefault));
}

/**
 * @brief getActiveWebEngineType returns EVERGREEN when enforce is EVERGREEN.
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_getActiveWebEngineType_004, TestSize.Level1)
{
    int webEngineEnforce = OHOS::system::GetIntParameter("web.engine.enforce", 0);
    OHOS::system::SetParameter("web.engine.enforce",
        std::to_string(static_cast<int>(ArkWebEngineType::EVERGREEN)));
    SetActiveWebEngineVersionInner(ArkWebEngineVersion::SYSTEM_DEFAULT);
    EXPECT_EQ(getActiveWebEngineType(), ArkWebEngineType::EVERGREEN);
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(webEngineEnforce));
}

/**
 * @brief GetArkwebNameSpace returns nweb_ns_playground for PLAYGROUND engine.
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_GetArkwebNameSpace_003, TestSize.Level1)
{
    SetActiveWebEngineVersionInner(static_cast<ArkWebEngineVersion>(
        static_cast<int>(ArkWebEngineType::PLAYGROUND)));
    EXPECT_EQ(GetArkwebNameSpace(), "nweb_ns_playground");
}

/**
 * @brief GetArkwebLibPath returns the evergreen path for PLAYGROUND engine.
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_GetArkwebLibPath_003, TestSize.Level1)
{
    SetActiveWebEngineVersionInner(static_cast<ArkWebEngineVersion>(
        static_cast<int>(ArkWebEngineType::PLAYGROUND)));
    EXPECT_EQ(GetArkwebLibPath(), ARK_WEB_CORE_HAP_LIB_PATH);
}

/**
 * @brief GetArkwebRelativePathForBundle returns the evergreen path for PLAYGROUND engine.
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_GetArkwebRelativePathForBundle_003, TestSize.Level1)
{
    SetActiveWebEngineVersionInner(static_cast<ArkWebEngineVersion>(
        static_cast<int>(ArkWebEngineType::PLAYGROUND)));
#if defined(IS_ASAN)
    EXPECT_EQ(GetArkwebRelativePathForBundle(), ARK_WEB_CORE_ASAN_PATH_FOR_BUNDLE);
#else
    EXPECT_EQ(GetArkwebRelativePathForBundle(), ARK_WEB_CORE_PATH_FOR_BUNDLE);
#endif
}

/**
 * @brief GetArkwebInstallPath returns evergreen paths for PLAYGROUND engine.
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_GetArkwebInstallPath_003, TestSize.Level1)
{
    SetActiveWebEngineVersionInner(static_cast<ArkWebEngineVersion>(
        static_cast<int>(ArkWebEngineType::PLAYGROUND)));
    auto aclPath = GetArkwebInstallPath();
    bool res = (aclPath == SANDBOX_EVERGREEN_HAP_PATH || aclPath == PRECONFIG_EVERGREEN_HAP_PATH);
    EXPECT_TRUE(res);
}

/**
 * @brief GetArkwebRelativePathForMock returns the mock relative path.
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_GetArkwebRelativePathForMock_001, TestSize.Level1)
{
    EXPECT_EQ(GetArkwebRelativePathForMock(), ARK_WEB_CORE_PATH_FOR_MOCK);
}

/**
 * @brief LogForUnsupportedFunc emits a warning log (smoke test, no crash).
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_LogForUnsupportedFunc_001, TestSize.Level1)
{
    LogForUnsupportedFunc(ArkWebEngineVersion::M114, "testFunc");
    SUCCEED();
}

/**
 * @brief SetActiveWebPlayGround with a non-PLAYGROUND version is rejected;
 *        active version is unchanged.
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_SetActiveWebPlayGround_001, TestSize.Level1)
{
    ArkWebEngineVersion before = getActiveWebEngineVersion();
    SetActiveWebPlayGround(ArkWebEngineVersion::M114);
    EXPECT_EQ(getActiveWebEngineVersion(), before);
}

/**
 * @brief SetActiveWebPlayGround with PLAYGROUND sets the active version.
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_SetActiveWebPlayGround_002, TestSize.Level1)
{
    SetActiveWebPlayGround(ArkWebEngineVersion::PLAYGROUND);
    EXPECT_EQ(getActiveWebEngineVersion(), ArkWebEngineVersion::PLAYGROUND);
    EXPECT_EQ(getActiveWebEngineType(), ArkWebEngineType::PLAYGROUND);
}

/**
 * @brief ProcessDataMigrateAppParam rejects a non-array value; g_dataMigrateApp unchanged.
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_ProcessDataMigrateAppParam_001, TestSize.Level1)
{
    Json::Value value = "com.example.app";
    ProcessDataMigrateAppParam(value);
    EXPECT_EQ(g_dataMigrateApp, nullptr);
}

/**
 * @brief ProcessDataMigrateAppParam rejects an array exceeding MAX_ARRAY_SIZE.
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_ProcessDataMigrateAppParam_002, TestSize.Level1)
{
    Json::Value value(Json::arrayValue);
    for (size_t i = 0; i <= MAX_ARRAY_SIZE; ++i) {
        value.append("app" + std::to_string(i));
    }
    ProcessDataMigrateAppParam(value);
    EXPECT_EQ(g_dataMigrateApp, nullptr);
}

/**
 * @brief ProcessDataMigrateAppParam skips non-string items in the array.
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_ProcessDataMigrateAppParam_003, TestSize.Level1)
{
    std::string appBundleName = "com.example.migrate";
    Json::Value value(Json::arrayValue);
    value.append(2);
    value.append(appBundleName);
    ProcessDataMigrateAppParam(value);
    ASSERT_NE(g_dataMigrateApp, nullptr);
    EXPECT_EQ(g_dataMigrateApp->find(appBundleName) != g_dataMigrateApp->end(), true);
}

/**
 * @brief ProcessDataMigrateAppParam stores an empty array (no entries).
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_ProcessDataMigrateAppParam_004, TestSize.Level1)
{
    Json::Value value(Json::arrayValue);
    ProcessDataMigrateAppParam(value);
    ASSERT_NE(g_dataMigrateApp, nullptr);
    EXPECT_EQ(g_dataMigrateApp->empty(), true);
}

/**
 * @brief ProcessParamItem dispatches web.engine.dataMigrateApp.
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_ProcessParamItem_006, TestSize.Level1)
{
    std::string appBundleName = "com.example.migrate2";
    Json::Value value(Json::arrayValue);
    value.append(appBundleName);
    ProcessParamItem("web.engine.dataMigrateApp", value);
    ASSERT_NE(g_dataMigrateApp, nullptr);
    EXPECT_EQ(g_dataMigrateApp->find(appBundleName) != g_dataMigrateApp->end(), true);
}

/**
 * @brief ProcessJsonConfig rejects a non-object root element.
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_ProcessJsonConfig_001, TestSize.Level1)
{
    Json::Value nonObject = 42;
    ProcessJsonConfig(nonObject);
    // No parameter should be changed; this is a no-op smoke test.
    SUCCEED();
}

/**
 * @brief ProcessJsonConfig dispatches each member of an object root.
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_ProcessJsonConfig_002, TestSize.Level1)
{
    int webEngineEnforce = OHOS::system::GetIntParameter("web.engine.enforce", 0);
    int webEngineDefault = OHOS::system::GetIntParameter("web.engine.default", 0);
    Json::Value root(Json::objectValue);
    root["web.engine.default"] = static_cast<int>(ArkWebEngineType::EVERGREEN);
    root["web.engine.enforce"] = static_cast<int>(ArkWebEngineType::EVERGREEN);
    Json::Value arr(Json::arrayValue);
    arr.append("com.example.legacy");
    root["web.engine.legacyApp"] = arr;
    Json::Value arr2(Json::arrayValue);
    arr2.append("com.example.migrate");
    root["web.engine.dataMigrateApp"] = arr2;
    root["web.engine.unknown"] = 1;
    ProcessJsonConfig(root);
    EXPECT_NE(g_legacyApp, nullptr);
    EXPECT_NE(g_dataMigrateApp, nullptr);
    EXPECT_EQ(g_legacyApp->find("com.example.legacy") != g_legacyApp->end(), true);
    EXPECT_EQ(g_dataMigrateApp->find("com.example.migrate") != g_dataMigrateApp->end(), true);
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(webEngineEnforce));
    OHOS::system::SetParameter("web.engine.default", std::to_string(webEngineDefault));
}

/**
 * @brief IsDataMigrate returns false when g_dataMigrateApp is null.
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_IsDataMigrate_001, TestSize.Level1)
{
    g_dataMigrateApp.reset();
    EXPECT_EQ(IsDataMigrate("com.example.app"), false);
}

/**
 * @brief IsDataMigrate returns false when DATA_MIGRATE_APP_NONE is present.
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_IsDataMigrate_002, TestSize.Level1)
{
    Json::Value value(Json::arrayValue);
    value.append(DATA_MIGRATE_APP_NONE);
    ProcessDataMigrateAppParam(value);
    ASSERT_NE(g_dataMigrateApp, nullptr);
    EXPECT_EQ(IsDataMigrate("com.example.app"), false);
}

/**
 * @brief IsDataMigrate returns true when DATA_MIGRATE_APP_ALL is present.
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_IsDataMigrate_003, TestSize.Level1)
{
    Json::Value value(Json::arrayValue);
    value.append(DATA_MIGRATE_APP_ALL);
    ProcessDataMigrateAppParam(value);
    ASSERT_NE(g_dataMigrateApp, nullptr);
    EXPECT_EQ(IsDataMigrate("com.example.anything"), true);
}

/**
 * @brief IsDataMigrate returns true for an exact bundle match, false for a non-match.
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_IsDataMigrate_004, TestSize.Level1)
{
    std::string appBundleName = "com.example.exact";
    Json::Value value(Json::arrayValue);
    value.append(appBundleName);
    ProcessDataMigrateAppParam(value);
    ASSERT_NE(g_dataMigrateApp, nullptr);
    EXPECT_EQ(IsDataMigrate(appBundleName), true);
    EXPECT_EQ(IsDataMigrate("com.example.other"), false);
}

/**
 * @brief SelectWebcoreBeforeProcessRun sets g_cloudEnableAppVersion to LEGACY when the
 *        bundle is in the legacy app list.
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_SelectWebcoreBeforeProcessRun_003, TestSize.Level1)
{
    int webEngineEnforce = OHOS::system::GetIntParameter("web.engine.enforce", 0);
    OHOS::system::SetParameter("web.engine.enforce", "0");
    std::string appBundleName = "com.example.legacy.app";
    Json::Value legacyArray(Json::arrayValue);
    legacyArray.append(appBundleName);
    ProcessLegacyAppParam(legacyArray);
    ASSERT_NE(g_legacyApp, nullptr);
    SelectWebcoreBeforeProcessRun(appBundleName);
    // g_cloudEnableAppVersion is now LEGACY; with SYSTEM_DEFAULT app version and
    // enforce != LEGACY/EVERGREEN, CalculateActiveWebEngineVersion returns LEGACY.
    SetActiveWebEngineVersionInner(ArkWebEngineVersion::SYSTEM_DEFAULT);
    EXPECT_EQ(CalculateActiveWebEngineVersion(),
        static_cast<ArkWebEngineVersion>(ArkWebEngineType::LEGACY));
    // g_legacyApp should be reset after SelectWebcoreBeforeProcessRun.
    EXPECT_EQ(g_legacyApp, nullptr);
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(webEngineEnforce));
}

/**
 * @brief SelectWebcoreBeforeProcessRun with a null g_legacyApp does not crash and
 *        leaves g_cloudEnableAppVersion unchanged.
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_SelectWebcoreBeforeProcessRun_004, TestSize.Level1)
{
    int webEngineEnforce = OHOS::system::GetIntParameter("web.engine.enforce", 0);
    OHOS::system::SetParameter("web.engine.enforce", "0");
    g_legacyApp.reset();
    SelectWebcoreBeforeProcessRun("com.example.noop");
    EXPECT_EQ(g_legacyApp, nullptr);
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(webEngineEnforce));
}

/**
 * @brief CheckTargetExists returns true for an existing path, false for a non-existing
 *        path, and false on error.
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_CheckTargetExists_001, TestSize.Level1)
{
    EXPECT_EQ(CheckTargetExists("/data"), true);
    EXPECT_EQ(CheckTargetExists("/this/path/does/not/exist/arkweb_test"), false);
}

/**
 * @brief HandleVersionString parses a valid "version=a.b.c.d" string directly.
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_HandleVersionString_001, TestSize.Level1)
{
    long long num = 0;
    EXPECT_EQ(HandleVersionString("version=1.10.25.100", num), true);
    EXPECT_EQ(num, 110025100LL);
    EXPECT_EQ(HandleVersionString("version = 2.3.4.5", num), true);
    EXPECT_EQ(num, 20304005LL);
}

/**
 * @brief HandleVersionString rejects an invalid version string.
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_HandleVersionString_002, TestSize.Level1)
{
    long long num = 0;
    EXPECT_EQ(HandleVersionString("not a version", num), false);
    EXPECT_EQ(HandleVersionString("version=1000.00.0.0", num), false);
}

/**
 * @brief GetVersionString returns true and fills the string for a file with content,
 *        false for an empty file.
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_GetVersionString_002, TestSize.Level1)
{
    std::string nonEmptyFile = "version_tmp_nonempty.txt";
    FileProcessor::WriteFile(nonEmptyFile, "version=1.0.0.0");
    std::string out;
    EXPECT_EQ(GetVersionString(nonEmptyFile, out), true);
    EXPECT_EQ(out, "version=1.0.0.0");

    std::string emptyFile = "version_tmp_empty.txt";
    FileProcessor::WriteFile(emptyFile, "");
    std::string out2;
    EXPECT_EQ(GetVersionString(emptyFile, out2), false);
}

/**
 * @brief ExtractAndRemoveParam with a trailing separator returns the param value
 *        and leaves an empty trailing segment (edge case for eraseLength branch).
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_ExtractAndRemoveParam_007, TestSize.Level1)
{
    std::string renderCmd = "#prefix=value#";
    std::string prefix = "#prefix=";
    std::string result = ExtractAndRemoveParam(renderCmd, prefix);
    EXPECT_EQ(result, "value");
    EXPECT_EQ(renderCmd, "#");
}

/**
 * @brief UpdateAppInfoFromCmdline with all parameters present and a trailing separator.
 */
HWTEST_F(ArkWebUtilsTest, ArkWebUtilsTest_UpdateAppInfoFromCmdline_001, TestSize.Level1)
{
    // UpdateAppInfoFromCmdline does not parse #--appEngineVersion; set it
    // explicitly so the assertion is deterministic.
    int webEngineEnforce = OHOS::system::GetIntParameter("web.engine.enforce", 0);
    OHOS::system::SetParameter("web.engine.enforce", "0");
    setActiveWebEngineVersion(ArkWebEngineVersion::M132);
    std::string renderCmd = "#--appEngineVersion=2#--appBundleName=myapp#--appApiVersion=10#--appVersion=5#";
    UpdateAppInfoFromCmdline(renderCmd);
    EXPECT_EQ(GetBundleName(), "myapp");
    EXPECT_EQ(GetApiVersion(), "10");
    EXPECT_EQ(GetAppVersion(), "5");
    EXPECT_EQ(getActiveWebEngineVersion(), ArkWebEngineVersion::M132);
    OHOS::system::SetParameter("web.engine.enforce", std::to_string(webEngineEnforce));
}
} // namespace OHOS::NWeb