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
    size_t len = hapPath.size();
    bool result = adapterImpl.GetRawFileData(hapPath, len, dest, true);
    EXPECT_FALSE(result);
    std::shared_ptr<Extractor> extractor = std::make_shared<Extractor>(hapPath);
    extractor->Init();
    extractor->initial_ = true;
    result = adapterImpl.GetRawFileData(extractor, hapPath, len, dest);
    EXPECT_FALSE(result);
    result = adapterImpl.GetRawFileData(nullptr, hapPath, len, dest);
    EXPECT_FALSE(result);
}
}
} // namespace NWeb