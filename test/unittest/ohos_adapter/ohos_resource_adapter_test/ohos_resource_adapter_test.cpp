/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include <cstdint>
#include <securec.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#define private public
#include "ohos_resource_adapter_impl.h"
#include "application_context.h"
#include "nweb_config_helper.h"
#include "extractor.h"
#include "system_properties_adapter_impl.h"
#undef private
#include "parameters.h"
#include "zip_file_reader.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AbilityBase;
using namespace OHOS::AbilityRuntime;

namespace OHOS {
namespace {
constexpr uint32_t MODULE_NAME_SIZE = 32;
const std::string NWEB_HAP_PATH = "/system/app/ArkWebCore/ArkWebCore.hap";
const std::string NWEB_HAP_PATH_1 = "/system/app/NWeb/NWeb.hap";
const std::string NWEB_HAP_PATH_2 = "/system/app/com.ohos.nweb/NWeb.hap";
const std::string ARKWEB_HAP_PATH_1 = "/system/app/com.ohos.arkwebcore/ArkWebCore.hap";
const std::string NWEB_HAP_PATH_MODULE_UPDATE = "/module_update/ArkWebCore/app/com.ohos.nweb/NWeb.hap";

std::shared_ptr<AbilityRuntime::ApplicationContext> g_applicationContext = nullptr;
}

namespace AbilityRuntime {
std::shared_ptr<ApplicationContext> Context::GetApplicationContext()
{
    return g_applicationContext;
}
} // namespace AbilityRuntime

namespace NWeb {
class OhosResourceAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void OhosResourceAdapterTest::SetUpTestCase(void)
{}

void OhosResourceAdapterTest::TearDownTestCase(void)
{}

void OhosResourceAdapterTest::SetUp(void)
{}

void OhosResourceAdapterTest::TearDown(void)
{}

class ApplicationContextMock : public ApplicationContext {
public:
    MOCK_CONST_METHOD0(GetResourceManager, std::shared_ptr<Global::Resource::ResourceManager>());
    MOCK_METHOD2(CreateModuleContext, std::shared_ptr<Context>(const std::string &, const std::string &));
};

class ExtractorMock : public Extractor{
public:
    explicit ExtractorMock() : Extractor("web_test") {}
    ~ExtractorMock() override = default;
    void SetInit(bool init)
    {
        initial_ = init;
    }

    void SetStageMode(bool isStageModel)
    {
        isStageModel_ = isStageModel;
    }
};

/**
 * @tc.name: OhosResourceAdapterTest_Init_001
 * @tc.desc: Init.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosResourceAdapterTest, OhosResourceAdapterTest_Init_001, TestSize.Level1)
{
    std::string hapPath = "/system/app/com.ohos.nweb/NWeb.hap";
    auto adapterImpl = std::make_shared<OhosResourceAdapterImpl>(hapPath);
    EXPECT_NE(adapterImpl, nullptr);
    hapPath.clear();
    adapterImpl->Init(hapPath);
}

/**
 * @tc.name: OhosResourceAdapterTest_GetRawFileData_002
 * @tc.desc: GetRawFileData.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosResourceAdapterTest, OhosResourceAdapterTest_GetRawFileData_002, TestSize.Level1)
{
    std::string hapPath = "/system/app/com.ohos.nweb/NWeb.hap";
    OhosResourceAdapterImpl adapterImpl(hapPath);
    std::unique_ptr<uint8_t[]> dest;
    std::string rawFile = "test_web";
    size_t len = rawFile.size();
    uint8_t* data;
    bool result = adapterImpl.GetRawFileData(rawFile, len, &data, true);
    EXPECT_FALSE(result);
    std::shared_ptr<Extractor> extractor = std::make_shared<Extractor>(rawFile);
    result = adapterImpl.GetRawFileData(extractor, rawFile, len, dest);
    EXPECT_FALSE(result);
    result = adapterImpl.GetRawFileData(nullptr, rawFile, len, dest);
    EXPECT_FALSE(result);
    auto mock = std::make_shared<ExtractorMock>();
    mock->SetStageMode(false);
    adapterImpl.GetRawFileData(mock, rawFile, len, dest);
    std::shared_ptr<OhosFileMapper> fileMapper = adapterImpl.GetRawFileMapper(rawFile, true);
    EXPECT_EQ(fileMapper, nullptr);
    result = adapterImpl.IsRawFileExist(rawFile, true);
    EXPECT_FALSE(result);
    uint16_t date;
    uint16_t time;
    result = adapterImpl.GetRawFileLastModTime(rawFile, date, time, true);
    EXPECT_FALSE(result);
    result = adapterImpl.GetRawFileLastModTime(rawFile, date, time, false);
    EXPECT_FALSE(result);
    time_t times;
    result = adapterImpl.GetRawFileLastModTime(rawFile, times, true);
    EXPECT_FALSE(result);
    result = adapterImpl.GetRawFileLastModTime(rawFile, times, false);
    EXPECT_FALSE(result);
    result = adapterImpl.HasEntry(extractor, rawFile);
    EXPECT_FALSE(result);
    result = adapterImpl.HasEntry(nullptr, rawFile);
    EXPECT_FALSE(result);
    std::shared_ptr<OhosFileMapper> mapper = adapterImpl.GetRawFileMapper(nullptr, rawFile);
    EXPECT_EQ(mapper, nullptr);
    mapper = adapterImpl.GetRawFileMapper(extractor, rawFile);
    EXPECT_EQ(mapper, nullptr);
    adapterImpl.sysExtractor_.reset();
    result = adapterImpl.GetRawFileLastModTime(rawFile, date, time, true);
    EXPECT_FALSE(result);
    result = adapterImpl.GetRawFileLastModTime(rawFile, times, true);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: OhosResourceAdapterTest_OhosFileMapperImpl_003
 * @tc.desc: OhosFileMapperImpl.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosResourceAdapterTest, OhosResourceAdapterTest_OhosFileMapperImpl_003, TestSize.Level1)
{
    std::string hapPath = "";
    if (access(NWEB_HAP_PATH.c_str(), F_OK) == 0) {
        hapPath = NWEB_HAP_PATH;
    }
    if (access(NWEB_HAP_PATH_1.c_str(), F_OK) == 0) {
        hapPath = NWEB_HAP_PATH_1;
    }
    if (access(NWEB_HAP_PATH_MODULE_UPDATE.c_str(), F_OK) == 0) {
        hapPath = NWEB_HAP_PATH_MODULE_UPDATE;
    }
    if (access(NWEB_HAP_PATH_2.c_str(), F_OK) == 0) {
        hapPath = NWEB_HAP_PATH_MODULE_UPDATE;
    }
    if (access(ARKWEB_HAP_PATH_1.c_str(), F_OK) == 0) {
        hapPath = NWEB_HAP_PATH_MODULE_UPDATE;
    }

    std::shared_ptr<Extractor> extractor = std::make_shared<Extractor>(hapPath);
    EXPECT_NE(extractor, nullptr);
    std::shared_ptr<OHOS::AbilityBase::ZipFileReader> fileReader =
        OHOS::AbilityBase::ZipFileReader::CreateZipFileReader(hapPath);
    if (fileReader == nullptr) {
        return;
    }
    EXPECT_NE(fileReader, nullptr);
    std::unique_ptr<OHOS::AbilityBase::FileMapper> fileMap = std::make_unique<OHOS::AbilityBase::FileMapper>();
    EXPECT_NE(fileMap, nullptr);
    fileMap->CreateFileMapper(fileReader, hapPath, 0, hapPath.size(), true);
    OhosFileMapperImpl apperImpl(std::move(fileMap), extractor);
    int32_t result = apperImpl.GetFd();
    EXPECT_EQ(result, -1);
    result = apperImpl.GetOffset();
    EXPECT_NE(result, -1);
    std::string fileNmae = apperImpl.GetFileName();
    EXPECT_NE(fileNmae, "");
    bool isCompressed = apperImpl.IsCompressed();
    EXPECT_TRUE(isCompressed);
    void* data = apperImpl.GetDataPtr();
    EXPECT_NE(data, nullptr);
    size_t dataLen = apperImpl.GetDataLen();
    EXPECT_NE(dataLen, 0);
    uint8_t* dest;
    isCompressed = apperImpl.UnzipData(&dest, dataLen);
    EXPECT_FALSE(isCompressed);
    apperImpl.extractor_.reset();
    isCompressed = apperImpl.UnzipData(&dest, dataLen);
    EXPECT_FALSE(isCompressed);
}

/**
 * @tc.name: OhosResourceAdapterTest_OhosFileMapperImpl_004
 * @tc.desc: OhosFileMapperImpl.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosResourceAdapterTest, OhosResourceAdapterTest_OhosFileMapperImpl_004, TestSize.Level1)
{
    std::string hapPath = "/system/app/com.ohos.nweb/NWeb.hap";
    OhosResourceAdapterImpl adapterImpl(hapPath);
    SystemPropertiesAdapterImpl& propImpl = SystemPropertiesAdapterImpl::GetInstance();
    bool optimode = propImpl.GetWebOptimizationValue();
    if (optimode) {
        OHOS::system::SetParameter("web.optimization", "false");
    }
    std::string rawFile = "test_web";
    std::shared_ptr<Extractor> extractor = std::make_shared<Extractor>(rawFile);
    std::shared_ptr<OhosFileMapper> mapper = adapterImpl.GetRawFileMapper(extractor, rawFile);
    EXPECT_EQ(mapper, nullptr);
    if (optimode) {
        OHOS::system::SetParameter("web.optimization", "true");
    }
}

/**
 * @tc.name: OhosResourceAdapterTest_ParseModuleName_004
 * @tc.desc: Init.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosResourceAdapterTest, OhosResourceAdapterTest_ParseModuleName_004, TestSize.Level1)
{
    std::string hapPath = "";
    if (access(NWEB_HAP_PATH.c_str(), F_OK) == 0) {
        hapPath = NWEB_HAP_PATH;
    }
    if (access(NWEB_HAP_PATH_1.c_str(), F_OK) == 0) {
        hapPath = NWEB_HAP_PATH_1;
    }
    if (access(NWEB_HAP_PATH_MODULE_UPDATE.c_str(), F_OK) == 0) {
        hapPath = NWEB_HAP_PATH_MODULE_UPDATE;
    }
    OhosResourceAdapterImpl adapterImpl(hapPath);
    bool newCreate = false;
    std::shared_ptr<Extractor> extractor = ExtractorUtil::GetExtractor(hapPath, newCreate);
    EXPECT_EQ(extractor, nullptr);
    std::string result = adapterImpl.GetModuleName(nullptr, 0);
    EXPECT_EQ(result, "");
    char *configStr = static_cast<char*>(malloc(MODULE_NAME_SIZE));
    EXPECT_NE(configStr, nullptr);
    (void)memset_s(configStr, MODULE_NAME_SIZE, 0, MODULE_NAME_SIZE);
    result = adapterImpl.GetModuleName(configStr, MODULE_NAME_SIZE);
    EXPECT_EQ(result, "");
    if (memcpy_s(configStr, MODULE_NAME_SIZE, "\"moduleName\"", sizeof("\"moduleName\"")) != EOK) {
        EXPECT_FALSE(true);
    };
    result = adapterImpl.GetModuleName(configStr, MODULE_NAME_SIZE);
    EXPECT_EQ(result, "");
    uint32_t len = strlen(configStr);
    if (memcpy_s(configStr + len, MODULE_NAME_SIZE - len, "\"", sizeof("\"")) != EOK) {
        EXPECT_FALSE(true);
    };
    result = adapterImpl.GetModuleName(configStr, MODULE_NAME_SIZE);
    EXPECT_EQ(result, "");
    (void)memset_s(configStr, MODULE_NAME_SIZE, 0, MODULE_NAME_SIZE);
    if (memcpy_s(configStr, MODULE_NAME_SIZE, "\"moduleName\"\"test\"", sizeof("\"moduleName\"\"test\"")) != EOK) {
        EXPECT_FALSE(true);
    };
    result = adapterImpl.GetModuleName(configStr, MODULE_NAME_SIZE);
    EXPECT_NE(result, "");
    result = adapterImpl.ParseModuleName(extractor);
    EXPECT_EQ(result, "");
    result = adapterImpl.ParseModuleName(nullptr);
    EXPECT_EQ(result, "");
    free(configStr);
    configStr = nullptr;
}

/**
 * @tc.name: OhosResourceAdapterTest_GetResourceMgr_005
 * @tc.desc: GetResourceMgr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosResourceAdapterTest, OhosResourceAdapterTest_GetResourceMgr_005, TestSize.Level1)
{
    std::string hapPath = "";
    if (access(NWEB_HAP_PATH.c_str(), F_OK) == 0) {
        hapPath = NWEB_HAP_PATH;
    }
    if (access(NWEB_HAP_PATH_1.c_str(), F_OK) == 0) {
        hapPath = NWEB_HAP_PATH_1;
    }
    if (access(NWEB_HAP_PATH_MODULE_UPDATE.c_str(), F_OK) == 0) {
        hapPath = NWEB_HAP_PATH_MODULE_UPDATE;
    }
    OhosResourceAdapterImpl adapterImpl(hapPath);
    uint8_t* dest;
    std::string rawFile = "test";
    size_t len = rawFile.size();
    bool result = adapterImpl.GetRawFileData(rawFile, len, &dest, false);
    EXPECT_FALSE(result);
    rawFile = "resources/rawfile/";
    len = rawFile.size();
    result = adapterImpl.GetRawFileData(rawFile, len, &dest, false);
    EXPECT_FALSE(result);
    rawFile = "resources/rawfile/bundleName";
    len = rawFile.size();
    result = adapterImpl.GetRawFileData(rawFile, len, &dest, false);
    EXPECT_FALSE(result);
    rawFile = "resources/rawfile/bundleName:";
    len = rawFile.size();
    result = adapterImpl.GetRawFileData(rawFile, len, &dest, false);
    EXPECT_FALSE(result);
    rawFile = "resources/rawfile/bundleName:test/";
    len = rawFile.size();
    result = adapterImpl.GetRawFileData(rawFile, len, &dest, false);
    EXPECT_FALSE(result);
    rawFile = "resources/rawfile/bundleName:test/moduleName:";
    len = rawFile.size();
    result = adapterImpl.GetRawFileData(rawFile, len, &dest, false);
    EXPECT_FALSE(result);
    rawFile = "resources/rawfile/bundleName:test/moduleName:web/";
    len = rawFile.size();
    result = adapterImpl.GetRawFileData(rawFile, len, &dest, false);
    EXPECT_FALSE(result);
    rawFile = "resources/rawfile/bundleName:test/moduleName:web/webtest";
    len = rawFile.size();
    result = adapterImpl.GetRawFileData(rawFile, len, &dest, false);
    EXPECT_FALSE(result);
    g_applicationContext = std::make_shared<ApplicationContextMock>();
    result = adapterImpl.GetRawFileData(rawFile, len, &dest, false);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: OhosResourceAdapterTest_GetResourceString_006
 * @tc.desc: GetResourceString.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosResourceAdapterTest, OhosResourceAdapterTest_GetResourceString_006, TestSize.Level1)
{
    std::string hapPath = "";
    if (access(NWEB_HAP_PATH.c_str(), F_OK) == 0) {
        hapPath = NWEB_HAP_PATH;
    }
    if (access(NWEB_HAP_PATH_1.c_str(), F_OK) == 0) {
        hapPath = NWEB_HAP_PATH_1;
    }
    if (access(NWEB_HAP_PATH_MODULE_UPDATE.c_str(), F_OK) == 0) {
        hapPath = NWEB_HAP_PATH_MODULE_UPDATE;
    }

    OhosResourceAdapterImpl adapterImpl(hapPath);
    std::string res;

    bool result = adapterImpl.GetResourceString("", "", 1, res);
    EXPECT_FALSE(result);

    result = adapterImpl.GetResourceString("test", "web", 1, res);
    EXPECT_FALSE(result);

    result = adapterImpl.GetResourceString("test", "web/webtest", 1, res);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: OhosResourceAdapterTest_GetSystemLanguage_007
 * @tc.desc: GetSystemLanguage.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosResourceAdapterTest, OhosResourceAdapterTest_GetSystemLanguage_007, TestSize.Level1)
{
    std::string hapPath = "";
    if (access(NWEB_HAP_PATH.c_str(), F_OK) == 0) {
        hapPath = NWEB_HAP_PATH;
    }
    if (access(NWEB_HAP_PATH_1.c_str(), F_OK) == 0) {
        hapPath = NWEB_HAP_PATH_1;
    }
    if (access(NWEB_HAP_PATH_MODULE_UPDATE.c_str(), F_OK) == 0) {
        hapPath = NWEB_HAP_PATH_MODULE_UPDATE;
    }

    OhosResourceAdapterImpl adapterImpl(hapPath);
    std::string res = adapterImpl.GetSystemLanguage();
    EXPECT_FALSE(res.empty());
}

HWTEST_F(OhosResourceAdapterTest, OhosResourceAdapterTest_ConvertToSandboxPath_008, TestSize.Level1)
{
    std::string hapPath = "";
    if (access(NWEB_HAP_PATH.c_str(), F_OK) == 0) {
        hapPath = NWEB_HAP_PATH;
    }
    if (access(NWEB_HAP_PATH_1.c_str(), F_OK) == 0) {
        hapPath = NWEB_HAP_PATH_1;
    }
    if (access(NWEB_HAP_PATH_MODULE_UPDATE.c_str(), F_OK) == 0) {
        hapPath = NWEB_HAP_PATH_MODULE_UPDATE;
    }

    OhosResourceAdapterImpl adapterImpl(hapPath);
    std::string inputStr = "";
    std::string prefixPath = "";
    std::string res = adapterImpl.ConvertToSandboxPath(inputStr, prefixPath);
    EXPECT_EQ(res, "");
    inputStr = NWEB_HAP_PATH;
    prefixPath = "/data/app/el1/bundle/public/";
    res = adapterImpl.ConvertToSandboxPath(inputStr, prefixPath);
    EXPECT_FALSE(res.empty());
    inputStr = "/data/app/el1/bundle/public/system/app/com.ohos.nweb/NWeb.hap";
    res = adapterImpl.ConvertToSandboxPath(inputStr, prefixPath);
    EXPECT_FALSE(res.empty());
}

HWTEST_F(OhosResourceAdapterTest, OhosResourceAdapterTest_SetArkWebCoreHapPathOverride_009, TestSize.Level1)
{
    std::string hapPath = "";
    if (access(NWEB_HAP_PATH.c_str(), F_OK) == 0) {
        hapPath = NWEB_HAP_PATH;
    }
    if (access(NWEB_HAP_PATH_1.c_str(), F_OK) == 0) {
        hapPath = NWEB_HAP_PATH_1;
    }
    if (access(NWEB_HAP_PATH_MODULE_UPDATE.c_str(), F_OK) == 0) {
        hapPath = NWEB_HAP_PATH_MODULE_UPDATE;
    }

    OhosResourceAdapterImpl adapterImpl(hapPath);
    adapterImpl.arkWebCoreHapPathOverride_ = "";
    std::string inputStr = "";
    adapterImpl.SetArkWebCoreHapPathOverride("");
    EXPECT_EQ(adapterImpl.arkWebCoreHapPathOverride_, "");
    inputStr = NWEB_HAP_PATH;
    adapterImpl.SetArkWebCoreHapPathOverride(inputStr);
    EXPECT_EQ(adapterImpl.arkWebCoreHapPathOverride_, NWEB_HAP_PATH);
    adapterImpl.arkWebCoreHapPathOverride_ = "";
}

#define RM_STUB_STATE(name, ...) \
    Global::Resource::RState name(__VA_ARGS__) override { return Global::Resource::ERROR; }
#define RM_STUB_BOOL(name, ...) bool name(__VA_ARGS__) override { return false; }
#define RM_STUB_VOID(name, ...) void name(__VA_ARGS__) override {}
#define RM_STUB_UINT(name, ...) uint32_t name(__VA_ARGS__) override { return 0; }
#define RM_STUB_STRING(name, ...) std::string name(__VA_ARGS__) override { return ""; }
#define RM_STUB_PTR(name, ...) \
    std::shared_ptr<Global::Resource::ResourceManager> name(__VA_ARGS__) override { return nullptr; }

class ResourceManagerMock : public Global::Resource::ResourceManager {
public:
    Global::Resource::RState stringState = Global::Resource::ERROR;
    Global::Resource::RState rawFileState = Global::Resource::ERROR;
    std::string stringValue;
    std::vector<uint8_t> rawData;

    Global::Resource::RState GetStringById(uint32_t id, std::string& outValue) override
    {
        if (stringState == Global::Resource::SUCCESS) {
            outValue = stringValue;
        }
        return stringState;
    }

    Global::Resource::RState GetRawFileFromHap(const std::string& rawFileName, size_t& len,
        std::unique_ptr<uint8_t[]>& outValue) override
    {
        if (rawFileState != Global::Resource::SUCCESS) {
            return rawFileState;
        }
        outValue = std::make_unique<uint8_t[]>(rawData.size());
        if (!rawData.empty()) {
            (void)memcpy_s(outValue.get(), rawData.size(), rawData.data(), rawData.size());
        }
        len = rawData.size();
        return Global::Resource::SUCCESS;
    }

    RM_STUB_BOOL(AddResource, const char*, const uint32_t&, bool)
    RM_STUB_STATE(UpdateResConfig, Global::Resource::ResConfig&, bool)
    RM_STUB_VOID(GetResConfig, Global::Resource::ResConfig&)
    RM_STUB_STATE(GetResConfigById, uint32_t, Global::Resource::ResConfig&, uint32_t)
    RM_STUB_STATE(GetResConfigByName, const std::string&, const Global::Resource::ResType,
        Global::Resource::ResConfig&, uint32_t)
    RM_STUB_STATE(GetStringByName, const char*, std::string&)
    RM_STUB_STATE(GetStringFormatById, std::string&, uint32_t, ...)
    RM_STUB_STATE(GetStringFormatByName, std::string&, const char*, ...)
    RM_STUB_STATE(GetStringArrayById, uint32_t, std::vector<std::string>&)
    RM_STUB_STATE(GetStringArrayByName, const char*, std::vector<std::string>&)
    RM_STUB_STATE(GetPatternById, uint32_t, std::map<std::string, std::string>&)
    RM_STUB_STATE(GetPatternByName, const char*, std::map<std::string, std::string>&)
    RM_STUB_STATE(GetPluralStringById, uint32_t, int, std::string&)
    RM_STUB_STATE(GetPluralStringByName, const char*, int, std::string&)
    RM_STUB_STATE(GetPluralStringByIdFormat, std::string&, uint32_t, int, ...)
    RM_STUB_STATE(GetPluralStringByNameFormat, std::string&, const char*, int, ...)
    RM_STUB_STATE(GetThemeById, uint32_t, std::map<std::string, std::string>&)
    RM_STUB_STATE(GetThemeByName, const char*, std::map<std::string, std::string>&)
    RM_STUB_STATE(GetBooleanById, uint32_t, bool&)
    RM_STUB_STATE(GetBooleanByName, const char*, bool&)
    RM_STUB_STATE(GetIntegerById, uint32_t, int&)
    RM_STUB_STATE(GetIntegerByName, const char*, int&)
    RM_STUB_STATE(GetFloatById, uint32_t, float&)
    RM_STUB_STATE(GetFloatById, uint32_t, float&, std::string&)
    RM_STUB_STATE(GetFloatByName, const char*, float&)
    RM_STUB_STATE(GetFloatByName, const char*, float&, std::string&)
    RM_STUB_STATE(GetIntArrayById, uint32_t, std::vector<int>&)
    RM_STUB_STATE(GetIntArrayByName, const char*, std::vector<int>&)
    RM_STUB_STATE(GetColorById, uint32_t, uint32_t&)
    RM_STUB_STATE(GetColorByName, const char*, uint32_t&)
    RM_STUB_STATE(GetProfileById, uint32_t, std::string&)
    RM_STUB_STATE(GetProfileByName, const char*, std::string&)
    RM_STUB_STATE(GetMediaById, uint32_t, std::string&, uint32_t)
    RM_STUB_STATE(GetMediaByName, const char*, std::string&, uint32_t)
    RM_STUB_STATE(GetRawFilePathByName, const std::string&, std::string&)
    RM_STUB_STATE(GetRawFileDescriptor, const std::string&, RawFileDescriptor&)
    RM_STUB_STATE(CloseRawFileDescriptor, const std::string&)
    RM_STUB_STATE(GetMediaDataById, uint32_t, size_t&, std::unique_ptr<uint8_t[]>&, uint32_t)
    RM_STUB_STATE(GetMediaDataByName, const char*, size_t&, std::unique_ptr<uint8_t[]>&, uint32_t)
    RM_STUB_STATE(GetMediaBase64DataById, uint32_t, std::string&, uint32_t)
    RM_STUB_STATE(GetMediaBase64DataByName, const char*, std::string&, uint32_t)
    RM_STUB_STATE(GetProfileDataById, uint32_t, size_t&, std::unique_ptr<uint8_t[]>&)
    RM_STUB_STATE(GetProfileDataByName, const char*, size_t&, std::unique_ptr<uint8_t[]>&)
    RM_STUB_STATE(GetRawFileDescriptorFromHap, const std::string&, RawFileDescriptor&)
    RM_STUB_STATE(IsLoadHap, std::string&)
    RM_STUB_STATE(GetRawFileList, const std::string&, std::vector<std::string>&)
    RM_STUB_STATE(GetDrawableInfoById, uint32_t, std::string&, size_t&, std::unique_ptr<uint8_t[]>&, uint32_t)
    RM_STUB_STATE(GetDrawableInfoByName, const char*, std::string&, size_t&, std::unique_ptr<uint8_t[]>&, uint32_t)
    RM_STUB_BOOL(AddResource, const std::string&, const std::vector<std::string>&)
    RM_STUB_BOOL(RemoveResource, const std::string&, const std::vector<std::string>&)
    RM_STUB_STATE(GetStringFormatById, uint32_t, std::string&,
        std::vector<std::tuple<NapiValueType, std::string>>&)
    RM_STUB_STATE(GetStringFormatByName, const char*, std::string&,
        std::vector<std::tuple<NapiValueType, std::string>>&)
    RM_STUB_UINT(GetResourceLimitKeys)
    RM_STUB_BOOL(AddAppOverlay, const std::string&)
    RM_STUB_BOOL(RemoveAppOverlay, const std::string&)
    RM_STUB_STATE(GetRawFdNdkFromHap, const std::string&, RawFileDescriptor&)
    RM_STUB_STATE(GetResId, const std::string&, uint32_t&)
    RM_STUB_VOID(GetLocales, std::vector<std::string>&, bool)
    RM_STUB_STATE(GetDrawableInfoById, uint32_t,
        std::tuple<std::string, size_t, std::string>&, std::unique_ptr<uint8_t[]>&, uint32_t, uint32_t)
    RM_STUB_STATE(GetDrawableInfoByName, const char*,
        std::tuple<std::string, size_t, std::string>&, std::unique_ptr<uint8_t[]>&, uint32_t, uint32_t)
    RM_STUB_STATE(GetSymbolById, uint32_t, uint32_t&)
    RM_STUB_STATE(GetSymbolByName, const char*, uint32_t&)
    RM_STUB_STATE(GetThemeIcons, uint32_t, std::pair<std::unique_ptr<uint8_t[]>, size_t>&,
        std::pair<std::unique_ptr<uint8_t[]>, size_t>&, uint32_t, const std::string&)
    RM_STUB_STRING(GetThemeMask)
    RM_STUB_BOOL(HasIconInTheme, const std::string&)
    RM_STUB_STATE(GetOtherIconsInfo, const std::string&, std::unique_ptr<uint8_t[]>&, size_t&, bool)
    RM_STUB_STATE(IsRawDirFromHap, const std::string&, bool&)
    RM_STUB_PTR(GetOverrideResourceManager, std::shared_ptr<Global::Resource::ResConfig>)
    RM_STUB_STATE(UpdateOverrideResConfig, Global::Resource::ResConfig&)
    RM_STUB_VOID(GetOverrideResConfig, Global::Resource::ResConfig&)
    RM_STUB_STATE(GetDynamicIcon, const std::string&, std::pair<std::unique_ptr<uint8_t[]>, size_t>&, uint32_t)
    RM_STUB_STATE(GetStringFormatById, std::string&, uint32_t, va_list)
    RM_STUB_STATE(GetStringFormatByName, std::string&, const char*, va_list)
    RM_STUB_STATE(GetFormatPluralStringById, std::string&, uint32_t, int,
        std::vector<std::tuple<NapiValueType, std::string>>&)
    RM_STUB_STATE(GetFormatPluralStringByName, std::string&, const char*, int,
        std::vector<std::tuple<NapiValueType, std::string>>&)
    RM_STUB_BOOL(AddPatchResource, const char*, const char*)
    RM_STUB_STATE(GetThemeDataByName, const char*, std::map<std::string, ResData>&)
    RM_STUB_STATE(GetThemeDataById, uint32_t, std::map<std::string, ResData>&)
    RM_STUB_STATE(GetPatternDataById, uint32_t, std::map<std::string, ResData>&)
    RM_STUB_STATE(GetPatternDataByName, const char*, std::map<std::string, ResData>&)
    RM_STUB_STATE(GetFormatPluralStringById, std::string&, uint32_t, Quantity, va_list)
    RM_STUB_STATE(GetFormatPluralStringById, std::string&, uint32_t, Quantity,
        std::vector<std::tuple<NapiValueType, std::string>>&)
    RM_STUB_STATE(GetFormatPluralStringByName, std::string&, const char*, Quantity, va_list)
    RM_STUB_STATE(GetFormatPluralStringByName, std::string&, const char*, Quantity,
        std::vector<std::tuple<NapiValueType, std::string>>&)
    RM_STUB_STATE(GetResName, uint32_t, std::string&)
};
#undef RM_STUB_STATE
#undef RM_STUB_BOOL
#undef RM_STUB_VOID
#undef RM_STUB_UINT
#undef RM_STUB_STRING
#undef RM_STUB_PTR

/**
 * @tc.name: OhosFileMapperImpl_NullFileMap_010
 * @tc.desc: getters and UnzipData with null fileMap / null extractor.
 * @tc.type: FUNC
 */
HWTEST_F(OhosResourceAdapterTest, OhosFileMapperImpl_NullFileMap_010, TestSize.Level1)
{
    OhosFileMapperImpl mapper(nullptr, nullptr);
    EXPECT_EQ(mapper.GetFd(), -1);
    EXPECT_EQ(mapper.GetOffset(), -1);
    EXPECT_EQ(mapper.GetFileName(), "");
    EXPECT_FALSE(mapper.IsCompressed());
    EXPECT_EQ(mapper.GetDataPtr(), nullptr);
    EXPECT_EQ(mapper.GetDataLen(), 0);
    uint8_t* dest = nullptr;
    size_t len = 0;
    EXPECT_FALSE(mapper.UnzipData(&dest, len));
}

/**
 * @tc.name: OhosFileMapperImpl_Uncompressed_011
 * @tc.desc: extractor exists but fileMap is not compressed.
 * @tc.type: FUNC
 */
HWTEST_F(OhosResourceAdapterTest, OhosFileMapperImpl_Uncompressed_011, TestSize.Level1)
{
    auto fileMap = std::make_unique<OHOS::AbilityBase::FileMapper>();
    auto extractor = std::make_shared<Extractor>("web_test");
    OhosFileMapperImpl mapper(std::move(fileMap), extractor);
    EXPECT_FALSE(mapper.IsCompressed());
    uint8_t* dest = nullptr;
    size_t len = 0;
    EXPECT_FALSE(mapper.UnzipData(&dest, len));
}

/**
 * @tc.name: ConvertToSandboxPath_TrailingSlash_012
 * @tc.desc: prefix matched but the last slash is the trailing slash.
 * @tc.type: FUNC
 */
HWTEST_F(OhosResourceAdapterTest, ConvertToSandboxPath_TrailingSlash_012, TestSize.Level1)
{
    std::string input = "/data/app/el1/bundle/public/foo/";
    std::string prefix = "/data/storage/el1/bundle/nweb/";
    std::string res = OhosResourceAdapterImpl::ConvertToSandboxPath(input, prefix);
    EXPECT_EQ(res, input);
}

/**
 * @tc.name: GetRawFileMapper_IsSysFalse_013
 * @tc.desc: isSys false ternary branch.
 * @tc.type: FUNC
 */
HWTEST_F(OhosResourceAdapterTest, GetRawFileMapper_IsSysFalse_013, TestSize.Level1)
{
    OhosResourceAdapterImpl adapterImpl("/system/app/com.ohos.nweb/NWeb.hap");
    std::shared_ptr<OhosFileMapper> mapper = adapterImpl.GetRawFileMapper("test_web", false);
    EXPECT_EQ(mapper, nullptr);
}

/**
 * @tc.name: IsRawFileExist_IsSysFalse_014
 * @tc.desc: isSys false ternary branch.
 * @tc.type: FUNC
 */
HWTEST_F(OhosResourceAdapterTest, IsRawFileExist_IsSysFalse_014, TestSize.Level1)
{
    OhosResourceAdapterImpl adapterImpl("/system/app/com.ohos.nweb/NWeb.hap");
    EXPECT_FALSE(adapterImpl.IsRawFileExist("test_web", false));
}

/**
 * @tc.name: GetResourceMgr_ModuleContext_015
 * @tc.desc: module context is created and its resource manager is null.
 * @tc.type: FUNC
 */
HWTEST_F(OhosResourceAdapterTest, GetResourceMgr_ModuleContext_015, TestSize.Level1)
{
    auto appMock = std::make_shared<ApplicationContextMock>();
    EXPECT_CALL(*appMock, CreateModuleContext(_, _)).WillRepeatedly(Return(appMock));
    EXPECT_CALL(*appMock, GetResourceManager()).WillRepeatedly(Return(nullptr));
    Mock::AllowLeak(appMock.get());
    g_applicationContext = appMock;
    std::string res;
    EXPECT_FALSE(OhosResourceAdapterImpl::GetResourceString("test", "web", 1, res));
    g_applicationContext = nullptr;
}

/**
 * @tc.name: GetResourceString_ManagerResult_016
 * @tc.desc: GetStringById returns SUCCESS and non-SUCCESS.
 * @tc.type: FUNC
 */
HWTEST_F(OhosResourceAdapterTest, GetResourceString_ManagerResult_016, TestSize.Level1)
{
    auto appMock = std::make_shared<ApplicationContextMock>();
    auto rm = std::make_shared<ResourceManagerMock>();
    EXPECT_CALL(*appMock, GetResourceManager()).WillRepeatedly(Return(rm));
    g_applicationContext = appMock;

    rm->stringState = Global::Resource::SUCCESS;
    rm->stringValue = "hello";
    std::string res;
    EXPECT_TRUE(OhosResourceAdapterImpl::GetResourceString("", "", 1, res));
    EXPECT_EQ(res, "hello");

    rm->stringState = Global::Resource::ERROR;
    EXPECT_FALSE(OhosResourceAdapterImpl::GetResourceString("", "", 1, res));
    g_applicationContext = nullptr;
}

/**
 * @tc.name: GetRawFileData_ResourceManagerResult_017
 * @tc.desc: GetRawFileFromHap returns SUCCESS and failure fallback.
 * @tc.type: FUNC
 */
HWTEST_F(OhosResourceAdapterTest, GetRawFileData_ResourceManagerResult_017, TestSize.Level1)
{
    auto appMock = std::make_shared<ApplicationContextMock>();
    auto rm = std::make_shared<ResourceManagerMock>();
    EXPECT_CALL(*appMock, CreateModuleContext(_, _)).WillRepeatedly(Return(appMock));
    EXPECT_CALL(*appMock, GetResourceManager()).WillRepeatedly(Return(rm));
    Mock::AllowLeak(appMock.get());
    Mock::AllowLeak(rm.get());
    g_applicationContext = appMock;

    OhosResourceAdapterImpl adapterImpl("/system/app/com.ohos.nweb/NWeb.hap");
    std::string rawFile = "resources/rawfile/bundleName:test/moduleName:web/webtest";
    size_t len = 0;
    uint8_t* dest = nullptr;

    rm->rawFileState = Global::Resource::SUCCESS;
    rm->rawData = {1, 2, 3};
    EXPECT_TRUE(adapterImpl.GetRawFileData(rawFile, len, &dest, false));
    EXPECT_EQ(len, 3);
    EXPECT_NE(dest, nullptr);
    delete[] dest;
    dest = nullptr;

    rm->rawFileState = Global::Resource::ERROR;
    EXPECT_FALSE(adapterImpl.GetRawFileData(rawFile, len, &dest, false));
    g_applicationContext = nullptr;
}

/**
 * @tc.name: GetRawFileData_StageModel_018
 * @tc.desc: IsStageModel true branch of the extractor based GetRawFileData.
 * @tc.type: FUNC
 */
HWTEST_F(OhosResourceAdapterTest, GetRawFileData_StageModel_018, TestSize.Level1)
{
    auto mock = std::make_shared<ExtractorMock>();
    mock->SetStageMode(true);
    std::unique_ptr<uint8_t[]> dest;
    size_t len = 0;
    EXPECT_FALSE(OhosResourceAdapterImpl::GetRawFileData(mock, "test_web", len, dest));
}

/**
 * @tc.name: GetRawFileMapper_Optimization_019
 * @tc.desc: both web.optimization values select a mapper path and return null fileMap.
 * @tc.type: FUNC
 */
HWTEST_F(OhosResourceAdapterTest, GetRawFileMapper_Optimization_019, TestSize.Level1)
{
    SystemPropertiesAdapterImpl& propImpl = SystemPropertiesAdapterImpl::GetInstance();
    bool optimode = propImpl.GetWebOptimizationValue();
    std::shared_ptr<Extractor> extractor = std::make_shared<Extractor>("test_web");

    OHOS::system::SetParameter("web.optimization", "true");
    EXPECT_EQ(OhosResourceAdapterImpl::GetRawFileMapper(extractor, "test_web"), nullptr);
    OHOS::system::SetParameter("web.optimization", "false");
    EXPECT_EQ(OhosResourceAdapterImpl::GetRawFileMapper(extractor, "test_web"), nullptr);

    OHOS::system::SetParameter("web.optimization", optimode ? "true" : "false");
}

/**
 * @tc.name: GetArkWebHapPath_Override_020
 * @tc.desc: override path exists, sandbox conversion and sys extractor creation are exercised.
 * @tc.type: FUNC
 */
HWTEST_F(OhosResourceAdapterTest, GetArkWebHapPath_Override_020, TestSize.Level1)
{
    std::string hapPath = "";
    if (access(NWEB_HAP_PATH.c_str(), F_OK) == 0) {
        hapPath = NWEB_HAP_PATH;
    }
    if (access(NWEB_HAP_PATH_1.c_str(), F_OK) == 0) {
        hapPath = NWEB_HAP_PATH_1;
    }
    if (access(NWEB_HAP_PATH_MODULE_UPDATE.c_str(), F_OK) == 0) {
        hapPath = NWEB_HAP_PATH_MODULE_UPDATE;
    }
    if (hapPath.empty()) {
        return;
    }
    OhosResourceAdapterImpl::SetArkWebCoreHapPathOverride(hapPath);
    OhosResourceAdapterImpl adapterImpl(hapPath);
    EXPECT_NE(adapterImpl.sysExtractor_, nullptr);
    OhosResourceAdapterImpl::SetArkWebCoreHapPathOverride("");
}
}
} // namespace NWeb
