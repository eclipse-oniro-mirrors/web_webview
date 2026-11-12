/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "arkweb_utils.cpp"
#include "parameters.h"
#include "system_properties_adapter_impl.h"

using namespace testing::ext;

namespace OHOS::ArkWeb {

namespace {

int g_openCallCount = 0;

const char* MockEngineVersionFunc()
{
    return "4.1.6.1-test";
}

const char* MockChromeVersionFunc()
{
    return "144";
}

void* MockLibOpenSuccess()
{
    g_openCallCount++;
    return reinterpret_cast<void*>(0x1234);
}

void* MockLibOpenFailure()
{
    g_openCallCount++;
    return nullptr;
}

void* MockSymbolFound(void* libHandler)
{
    (void)libHandler;
    return reinterpret_cast<void*>(&MockEngineVersionFunc);
}

void* MockChromeSymbolFound(void* libHandler)
{
    (void)libHandler;
    return reinterpret_cast<void*>(&MockChromeVersionFunc);
}

void* MockSymbolNotFound(void* libHandler)
{
    (void)libHandler;
    return nullptr;
}

void ResetVersionResolveState()
{
    g_engineVersionResolved.store(false);
    g_engineVersionLibHandler = nullptr;
    g_engineVersionSymbolFunc = nullptr;
    g_engineVersionCacheResult = ArkWebVersionResolveResult::OK;
    g_engineVersionLibOpener = nullptr;
    g_engineVersionSymbolResolver = nullptr;
    g_chromeVersionResolved.store(false);
    g_chromeVersionSymbolFunc = nullptr;
    g_chromeVersionCacheResult = ArkWebVersionResolveResult::OK;
    g_chromeVersionSymbolResolver = nullptr;
    g_openCallCount = 0;
}

} // namespace

class ArkWebVersionUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ArkWebVersionUtilsTest::SetUpTestCase(void) {}

void ArkWebVersionUtilsTest::TearDownTestCase(void) {}

void ArkWebVersionUtilsTest::SetUp(void)
{
    ResetVersionResolveState();
}

void ArkWebVersionUtilsTest::TearDown(void)
{
    ResetVersionResolveState();
}

/**
 * @tc.name: GetChromeCompatibleVersionStringFromEngineTest001
 * @tc.desc: Success path returns the chrome version string via dlsym-resolved symbol.
 */
HWTEST_F(ArkWebVersionUtilsTest, GetChromeCompatibleVersionStringFromEngineTest001, TestSize.Level1)
{
    g_engineVersionLibOpener = &MockLibOpenSuccess;
    g_chromeVersionSymbolResolver = &MockChromeSymbolFound;

    std::string version;
    ArkWebVersionResolveResult result = GetChromeCompatibleVersionStringFromEngine(version);
    EXPECT_EQ(result, ArkWebVersionResolveResult::OK);
    EXPECT_EQ(version, "144");
    EXPECT_EQ(GetChromeCompatibleVersionStringFromEngine(), "144");
}

/**
 * @tc.name: GetChromeCompatibleVersionStringFromEngine_Fallback001
 * @tc.desc: Library open failure returns empty string with LIB_OPEN_FAILURE.
 */
HWTEST_F(ArkWebVersionUtilsTest, GetChromeCompatibleVersionStringFromEngine_Fallback001, TestSize.Level1)
{
    g_engineVersionLibOpener = &MockLibOpenFailure;
    g_chromeVersionSymbolResolver = &MockChromeSymbolFound;

    std::string version = "sentinel";
    ArkWebVersionResolveResult result = GetChromeCompatibleVersionStringFromEngine(version);
    EXPECT_EQ(result, ArkWebVersionResolveResult::LIB_OPEN_FAILURE);
    EXPECT_TRUE(version.empty());
    EXPECT_TRUE(GetChromeCompatibleVersionStringFromEngine().empty());
}

/**
 * @tc.name: GetChromeCompatibleVersionStringFromEngine_Fallback002
 * @tc.desc: Missing symbol returns empty string with SYMBOL_NOT_FOUND.
 */
HWTEST_F(ArkWebVersionUtilsTest, GetChromeCompatibleVersionStringFromEngine_Fallback002, TestSize.Level1)
{
    g_engineVersionLibOpener = &MockLibOpenSuccess;
    g_chromeVersionSymbolResolver = &MockSymbolNotFound;

    std::string version = "sentinel";
    ArkWebVersionResolveResult result = GetChromeCompatibleVersionStringFromEngine(version);
    EXPECT_EQ(result, ArkWebVersionResolveResult::SYMBOL_NOT_FOUND);
    EXPECT_TRUE(version.empty());
    EXPECT_TRUE(GetChromeCompatibleVersionStringFromEngine().empty());
}

/**
 * @tc.name: GetChromeCompatibleVersionStringFromEngine_Cached001
 * @tc.desc: The library is opened only once; subsequent calls reuse the cached symbol.
 */
HWTEST_F(ArkWebVersionUtilsTest, GetChromeCompatibleVersionStringFromEngine_Cached001, TestSize.Level1)
{
    g_engineVersionLibOpener = &MockLibOpenSuccess;
    g_chromeVersionSymbolResolver = &MockChromeSymbolFound;

    std::string first;
    ASSERT_EQ(GetChromeCompatibleVersionStringFromEngine(first), ArkWebVersionResolveResult::OK);
    EXPECT_EQ(g_openCallCount, 1);

    std::string second;
    ASSERT_EQ(GetChromeCompatibleVersionStringFromEngine(second), ArkWebVersionResolveResult::OK);
    EXPECT_EQ(g_openCallCount, 1);
    EXPECT_EQ(first, second);
}

/**
 * @tc.name: GetArkWebVersionStringFromEngineTest001
 * @tc.desc: Success path returns the version string via dlsym-resolved symbol.
 */
HWTEST_F(ArkWebVersionUtilsTest, GetArkWebVersionStringFromEngineTest001, TestSize.Level1)
{
    g_engineVersionLibOpener = &MockLibOpenSuccess;
    g_engineVersionSymbolResolver = &MockSymbolFound;

    std::string version;
    ArkWebVersionResolveResult result = GetArkWebVersionStringFromEngine(version);
    EXPECT_EQ(result, ArkWebVersionResolveResult::OK);
    EXPECT_EQ(version, "4.1.6.1-test");
    EXPECT_EQ(GetArkWebVersionStringFromEngine(), "4.1.6.1-test");
}

/**
 * @tc.name: GetArkWebVersionStringFromEngine_Fallback001
 * @tc.desc: Library open failure returns empty string with LIB_OPEN_FAILURE.
 */
HWTEST_F(ArkWebVersionUtilsTest, GetArkWebVersionStringFromEngine_Fallback001, TestSize.Level1)
{
    g_engineVersionLibOpener = &MockLibOpenFailure;
    g_engineVersionSymbolResolver = &MockSymbolFound;

    std::string version = "sentinel";
    ArkWebVersionResolveResult result = GetArkWebVersionStringFromEngine(version);
    EXPECT_EQ(result, ArkWebVersionResolveResult::LIB_OPEN_FAILURE);
    EXPECT_TRUE(version.empty());
    EXPECT_TRUE(GetArkWebVersionStringFromEngine().empty());
}

/**
 * @tc.name: GetArkWebVersionStringFromEngine_Fallback002
 * @tc.desc: Missing symbol returns empty string with SYMBOL_NOT_FOUND.
 */
HWTEST_F(ArkWebVersionUtilsTest, GetArkWebVersionStringFromEngine_Fallback002, TestSize.Level1)
{
    g_engineVersionLibOpener = &MockLibOpenSuccess;
    g_engineVersionSymbolResolver = &MockSymbolNotFound;

    std::string version = "sentinel";
    ArkWebVersionResolveResult result = GetArkWebVersionStringFromEngine(version);
    EXPECT_EQ(result, ArkWebVersionResolveResult::SYMBOL_NOT_FOUND);
    EXPECT_TRUE(version.empty());
    EXPECT_TRUE(GetArkWebVersionStringFromEngine().empty());
}

/**
 * @tc.name: GetArkWebVersionStringFromEngine_Cached001
 * @tc.desc: The library is opened only once; subsequent calls reuse the cached symbol.
 */
HWTEST_F(ArkWebVersionUtilsTest, GetArkWebVersionStringFromEngine_Cached001, TestSize.Level1)
{
    g_engineVersionLibOpener = &MockLibOpenSuccess;
    g_engineVersionSymbolResolver = &MockSymbolFound;

    std::string first;
    ASSERT_EQ(GetArkWebVersionStringFromEngine(first), ArkWebVersionResolveResult::OK);
    EXPECT_EQ(g_openCallCount, 1);

    std::string second;
    ASSERT_EQ(GetArkWebVersionStringFromEngine(second), ArkWebVersionResolveResult::OK);
    EXPECT_EQ(g_openCallCount, 1);
    EXPECT_EQ(first, second);
}

/**
 * @tc.name: GetArkWebVersionStringFromEngine_Cached002
 * @tc.desc: A failed resolution is cached and not retried within the process.
 */
HWTEST_F(ArkWebVersionUtilsTest, GetArkWebVersionStringFromEngine_Cached002, TestSize.Level1)
{
    g_engineVersionLibOpener = &MockLibOpenFailure;
    g_engineVersionSymbolResolver = &MockSymbolFound;

    std::string version;
    ASSERT_EQ(GetArkWebVersionStringFromEngine(version), ArkWebVersionResolveResult::LIB_OPEN_FAILURE);
    EXPECT_EQ(g_openCallCount, 1);

    ASSERT_EQ(GetArkWebVersionStringFromEngine(version), ArkWebVersionResolveResult::LIB_OPEN_FAILURE);
    EXPECT_EQ(g_openCallCount, 1);
}

/**
 * @tc.name: GetArkWebVersionStringFromEngine_NoInitFlag001
 * @tc.desc: Resolving the version symbol must not set g_webEngineInitFlag.
 */
HWTEST_F(ArkWebVersionUtilsTest, GetArkWebVersionStringFromEngine_NoInitFlag001, TestSize.Level1)
{
    g_engineVersionLibOpener = &MockLibOpenSuccess;
    g_engineVersionSymbolResolver = &MockSymbolFound;

    // Verify the flag is not modified regardless of its initial value.
    g_webEngineInitFlag = true;
    std::string version;
    ASSERT_EQ(GetArkWebVersionStringFromEngine(version), ArkWebVersionResolveResult::OK);
    EXPECT_TRUE(g_webEngineInitFlag);

    ResetVersionResolveState();
    g_webEngineInitFlag = false;
    g_engineVersionLibOpener = &MockLibOpenSuccess;
    g_engineVersionSymbolResolver = &MockSymbolFound;
    version.clear();
    ASSERT_EQ(GetArkWebVersionStringFromEngine(version), ArkWebVersionResolveResult::OK);
    EXPECT_FALSE(g_webEngineInitFlag);
}

} // namespace OHOS::ArkWeb
