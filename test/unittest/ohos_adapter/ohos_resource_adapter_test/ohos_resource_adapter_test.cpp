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

#include <cstring>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#define private public
#include "ohos_resource_adapter_impl.h"
#undef private

#include "extractor.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AbilityBase;

namespace OHOS {
namespace {
std::shared_ptr<Extractor> g_extractor = nullptr;
} // namespace

std::shared_ptr<Extractor> ExtractorUtil::GetExtractor(const std::string &hapPath, bool &newCreate)
{
    return g_extractor;
}

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

/**
 * @tc.name: OhosResourceAdapterTest_Init_001
 * @tc.desc: Init.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosResourceAdapterTest, OhosResourceAdapterTest_Init_001, TestSize.Level1)
{
    std::string hapPath = "/system/app/com.ohos.nweb/NWeb.hap";
    OhosResourceAdapterImpl adapterImpl(hapPath);
    g_extractor = std::make_shared<Extractor>(hapPath);
    adapterImpl.Init(hapPath);
    hapPath.clear();
    adapterImpl.Init(hapPath);
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
    bool result = adapterImpl.GetRawFileData(rawFile, len, dest, true);
    EXPECT_FALSE(result);
    std::shared_ptr<Extractor> extractor = std::make_shared<Extractor>(rawFile);
    result = adapterImpl.GetRawFileData(extractor, rawFile, len, dest);
    EXPECT_FALSE(result);
    result = adapterImpl.GetRawFileData(nullptr, rawFile, len, dest);
    EXPECT_FALSE(result);
    std::unique_ptr<OhosFileMapper> fileMapper = nullptr;
    result = adapterImpl.GetRawFileMapper(rawFile, fileMapper, true);
    EXPECT_FALSE(result);
    result = adapterImpl.IsRawFileExist(rawFile, true);
    EXPECT_FALSE(result);
    uint16_t date;
    uint16_t time;
    result = adapterImpl.GetRawFileLastModTime(rawFile, date, time, true);
    EXPECT_FALSE(result);
    time_t times;
    result = adapterImpl.GetRawFileLastModTime(rawFile, times, true);
    EXPECT_FALSE(result);
    result = adapterImpl.HasEntry(extractor, rawFile);
    EXPECT_FALSE(result);
    result = adapterImpl.HasEntry(nullptr, rawFile);
    EXPECT_FALSE(result);
    std::unique_ptr<OhosFileMapper> mapper = nullptr;
    result = adapterImpl.GetRawFileMapper(nullptr, rawFile, mapper);
    EXPECT_FALSE(result);
    result = adapterImpl.GetRawFileMapper(extractor, rawFile, mapper);
    EXPECT_FALSE(result);
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
    std::string rawFile = "test_web";
    size_t len = rawFile.size();
    std::shared_ptr<Extractor> extractor = std::make_shared<Extractor>(rawFile);
    std::unique_ptr<OHOS::AbilityBase::FileMapper> fileMap = std::make_unique<OHOS::AbilityBase::FileMapper>();
    fileMap->CreateFileMapper(rawFile, true, 0, 1, len);
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
    EXPECT_EQ(data, nullptr);
    size_t dataLen = apperImpl.GetDataLen();
    EXPECT_NE(dataLen, 0);
    std::unique_ptr<uint8_t[]> dest;
    isCompressed = apperImpl.UnzipData(dest, dataLen);
    EXPECT_FALSE(isCompressed);
    apperImpl.extractor_.reset();
    isCompressed = apperImpl.UnzipData(dest, dataLen);
    EXPECT_FALSE(isCompressed);
}
}
} // namespace NWeb