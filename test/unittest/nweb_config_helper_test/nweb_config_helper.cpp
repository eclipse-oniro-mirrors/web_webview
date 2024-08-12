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
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <unordered_map>

#include "nweb_config_helper.h"
#include "nweb_init_params.h"

using namespace testing;

namespace OHOS {
namespace NWebConfig {

class NWebConfigHelperTest : public ::testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void TearDown();

protected:
    std::shared_ptr<NWebEngineInitArgsImpl> initArgs;
    NWebConfigHelper nWebConfigHelper;
    void SetUp() override
    {
        initArgs = std::make_shared<NWebEngineInitArgsImpl>();
    }
};

HWTEST_F(NWebConfigHelperTest, ParseWebConfigXml_FileNotFound, TestSize.Level0)
{
    std::string configFilePath = "nonexistent.xml";
    EXPECT_NO_THROW(NWebConfigHelper::Instance().ParseWebConfigXml(configFilePath, initArgs));
}

HWTEST_F(NWebConfigHelperTest, ParseWebConfigXml_InvalidRootElement, TestSize.Level0)
{
    std::string configFilePath = "invalid_root.xml";
    EXPECT_NO_THROW(NWebConfigHelper::Instance().ParseWebConfigXml(configFilePath, initArgs));
}

HWTEST_F(NWebConfigHelperTest, ParseWebConfigXml_ValidInitConfig, TestSize.Level0)
{
    std::string configFilePath = "valid_init.xml";
    EXPECT_NO_THROW(NWebConfigHelper::Instance().ParseWebConfigXml(configFilePath, initArgs));
}

HWTEST_F(NWebConfigHelperTest, ParseWebConfigXml_ValidDeleteConfig, TestSize.Level0)
{
    std::string configFilePath = "valid_delete.xml";
    EXPECT_NO_THROW(NWebConfigHelper::Instance().ParseWebConfigXml(configFilePath, initArgs));
}

HWTEST_F(NWebConfigHelperTest, ParseWebConfigXml_ValidPerformanceConfig, TestSize.Level0)
{
    std::string configFilePath = "valid_performance.xml";
    EXPECT_NO_THROW(NWebConfigHelper::Instance().ParseWebConfigXml(configFilePath, initArgs));
}

HWTEST_F(NWebConfigHelperTest, ParseWebConfigXml_ValidLTPOConfig, TestSize.Level0)
{
    std::string configFilePath = "valid_ltpo.xml";
    EXPECT_NO_THROW(NWebConfigHelper::Instance().ParseWebConfigXml(configFilePath, initArgs));
}


HWTEST_F(NWebConfigHelperTest, GetPerfConfig_ShouldReturnEmptyVector_WhenSettingNameNotExist, TestSize.Level0)
{
    std::string settingName = "NonExistentSetting";
    std::vector<FrameRateSetting> result = NWebConfigHelper::Instance().GetPerfConfig(settingName);
    EXPECT_TRUE(result.empty());
}

HWTEST_F(NWebConfigHelperTest, GetPerfConfig_ShouldReturnNonEmptyVector_WhenSettingNameExist, TestSize.Level0)
{
    std::string settingName = "ExistentSetting";
    NWebConfigHelper::Instance().ltpoConfig_[settingName] = {FrameRateSetting(30)};
    std::vector<FrameRateSetting> result = NWebConfigHelper::Instance().GetPerfConfig(settingName);
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(result[0].frameRate, 30);
}

HWTEST_F(NWebConfigHelperTest, ParsePerfConfig_ShouldReturnEmptyString_WhenConfigNotFound, TestSize.Level0)
{
    std::string configNodeName = "non_existent_config";
    std::string argsNodeName = "non_existent_args";
    std::string result = NWebConfigHelper::Instance().ParsePerfConfig(configNodeName, argsNodeName);
    EXPECT_EQ(result, "");
}

HWTEST_F(NWebConfigHelperTest, ParsePerfConfig_ShouldReturnValue_WhenConfigFound, TestSize.Level0)
{
    std::string configNodeName = "existent_config";
    std::string argsNodeName = "existent_args";
    std::string expectedValue = "expected_value";
    NWebConfigHelper::Instance().perfConfig_[configNodeName + "/" + argsNodeName] = expectedValue;
    std::string result = NWebConfigHelper::Instance().ParsePerfConfig(configNodeName, argsNodeName);
    EXPECT_EQ(result, expectedValue);
}

HWTEST_F(NWebConfigHelperTest, ParsePerfConfig_NullNode, TestSize.Level0)
{
    xmlNodePtr node = nullptr;
    NWebConfigHelper::Instance().ParsePerfConfig(node);
    EXPECT_TRUE(NWebConfigHelper::Instance().perfConfig_.empty());
}

HWTEST_F(NWebConfigHelperTest, ParsePerfConfig_CommentNode, TestSize.Level0)
{
    xmlNodePtr node = xmlNewNode(nullptr, "comment");
    NWebConfigHelper::Instance().ParsePerfConfig(node);
    EXPECT_TRUE(NWebConfigHelper::Instance().perfConfig_.empty());
    xmlFreeNode(node);
}

HWTEST_F(NWebConfigHelperTest, ParsePerfConfig_ValidNode, TestSize.Level0)
 {
    xmlNodePtr node = xmlNewNode(nullptr, "node");
    xmlNodePtr childNode = xmlNewNode(nullptr, "childNode");
    xmlNodeAddContent(childNode, "value");
    xmlAddChild(node, childNode);
    NWebConfigHelper::Instance().ParsePerfConfig(node);
    EXPECT_EQ(hNWebConfigHelper::Instance().perfConfig_["node/childNode"], "value");
    xmlFreeNode(childNode);
    xmlFreeNode(node);
}

HWTEST_F(NWebConfigHelperTest, ParsePerfConfig_InvalidChildNode, TestSize.Level0)
 {
    xmlNodePtr node = xmlNewNode(nullptr, "node");
    xmlNodePtr childNode = xmlNewNode(nullptr, "comment");
    xmlAddChild(node, childNode);
    NWebConfigHelper::Instance().ParsePerfConfig(node);
    EXPECT_TRUE(NWebConfigHelper::Instance().perfConfig_.empty());
    xmlFreeNode(childNode);
    xmlFreeNode(node);
}

HWTEST_F(NWebConfigHelperTest, ParsePerfConfig_NullContent, TestSize.Level0)
 {
    xmlNodePtr node = xmlNewNode(nullptr, "node");
    xmlNodePtr childNode = xmlNewNode(nullptr, "childNode");
    xmlAddChild(node, childNode);
    NWebConfigHelper::Instance().ParsePerfConfig(node);
    EXPECT_TRUE(NWebConfigHelper::Instance().perfConfig_.empty());
    xmlFreeNode(childNode);
    xmlFreeNode(node);
 }


HWTEST_F(NWebConfigHelperTest, ParseDeleteConfig_NullRootPtr, TestSize.Level0)
{
    xmlNodePtr rootPtr = nullptr;
    std::string result = NWebConfigHelper::Instance().ParseDeleteConfig(rootPtr, initArgs);
    EXPECT_NULL(result);
}


HWTEST_F(NWebConfigHelperTest, ParseDeleteConfig_ValidNode) {
    xmlNodePtr rootPtr = xmlNewNode(nullptr, "valid");
    xmlNodePtr childNodePtr = xmlNewNode(nullptr, "child");
    xmlAddChild(rootPtr, childNodePtr);
    xmlChar *content = xmlNodeGetContent(childNodePtr);
    xmlNodeSetContent(childNodePtr, content);
    xmlFree(content);
    NWebConfigHelper::Instance().ParseDeleteConfig(rootPtr, initArgs);
}

HWTEST_F(NWebConfigHelperTest, ParseDeleteConfig_InvalidChildNode) {
    xmlNodePtr rootPtr = xmlNewNode(nullptr, "valid");
    xmlNodePtr childNodePtr = xmlNewNode(nullptr, "invalid");
    xmlAddChild(rootPtr, childNodePtr);
    NWebConfigHelper::Instance().ParseDeleteConfig(rootPtr, initArgs);
}

HWTEST_F(NWebConfigHelperTest, ParseDeleteConfig_NullContent) {
    xmlNodePtr rootPtr = xmlNewNode(nullptr, "valid");
    xmlNodePtr childNodePtr = xmlNewNode(nullptr, "child");
    xmlAddChild(rootPtr, childNodePtr);
    NWebConfigHelper::Instance().ParseDeleteConfig(rootPtr, initArgs);
}

HWTEST_F(NWebConfigHelperTest, ParseDeleteConfig_NotFoundConfig) {
    xmlNodePtr rootPtr = xmlNewNode(nullptr, "valid");
    xmlNodePtr childNodePtr = xmlNewNode(nullptr, "child");
    xmlAddChild(rootPtr, childNodePtr);
    xmlChar *content = xmlNodeGetContent(childNodePtr);
    xmlNodeSetContent(childNodePtr, content);
    xmlFree(content);
    NWebConfigHelper::Instance().ParseDeleteConfig(rootPtr, initArgs);
}

HWTEST_F(NWebConfigHelperTest, ParseDeleteConfig_EmptyParam) {
    xmlNodePtr rootPtr = xmlNewNode(nullptr, "valid");
    xmlNodePtr childNodePtr = xmlNewNode(nullptr, "child");
    xmlAddChild(rootPtr, childNodePtr);
    xmlChar *content = xmlNodeGetContent(childNodePtr);
    xmlNodeSetContent(childNodePtr, content);
    xmlFree(content);
    NWebConfigHelper::Instance().ParseDeleteConfig(rootPtr, initArgs);
}

} // NWebConfig
} // OHOS```