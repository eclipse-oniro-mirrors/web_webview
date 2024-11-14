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

protected:
    std::shared_ptr<NWebEngineInitArgsImpl> initArgs;
    NWebConfigHelper nWebConfigHelper;
    xmlNodePtr rootElement;
    xmlNodePtr childNodePtr;
    std::unique_ptr<xmlChar[]> content;
    void SetUp() override
    {
        initArgs = std::make_shared<NWebEngineInitArgsImpl>();
        rootElement = xmlNewNode(NULL, BAD_CAST "root");
        childNodePtr = xmlNewNode(NULL, BAD_CAST "child");
        int contentSize = 10;
        content = std::make_unique<xmlChar[]>(contentSize);
    }
    void TearDown() override {
        if (rootElement != nullptr) {
            xmlFreeNode(rootElement);
        }
        if (childNodePtr != nullptr) {
            xmlFreeNode(childNodePtr);
        }
    }
};

/**
 * @tc.name: ParseWebConfigXml_FileNotFound
 * @tc.desc: ParseWebConfigXml.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NWebConfigHelperTest, ParseWebConfigXml_FileNotFound, TestSize.Level0)
{
    std::string configFilePath = "nonexistent.xml";
    EXPECT_NO_THROW(NWebConfigHelper::Instance().ParseWebConfigXml(configFilePath, initArgs));
}

/**
 * @tc.name: ParseWebConfigXml_InvalidRootElement
 * @tc.desc: ParseWebConfigXml.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NWebConfigHelperTest, ParseWebConfigXml_InvalidRootElement, TestSize.Level0)
{
    std::string configFilePath = "invalid_root.xml";
    EXPECT_NO_THROW(NWebConfigHelper::Instance().ParseWebConfigXml(configFilePath, initArgs));
}

/**
 * @tc.name: ParseWebConfigXml_ValidInitConfig
 * @tc.desc: ParseWebConfigXml.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NWebConfigHelperTest, ParseWebConfigXml_ValidInitConfig, TestSize.Level0)
{
    std::string configFilePath = "valid_init.xml";
    EXPECT_NO_THROW(NWebConfigHelper::Instance().ParseWebConfigXml(configFilePath, initArgs));
}

/**
 * @tc.name: ParseWebConfigXml_ValidDeleteConfig
 * @tc.desc: ParseWebConfigXml.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NWebConfigHelperTest, ParseWebConfigXml_ValidDeleteConfig, TestSize.Level0)
{
    std::string configFilePath = "valid_delete.xml";
    EXPECT_NO_THROW(NWebConfigHelper::Instance().ParseWebConfigXml(configFilePath, initArgs));
}

/**
 * @tc.name: ParseWebConfigXml_ValidPerformanceConfig
 * @tc.desc:ParseWebConfigXml.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NWebConfigHelperTest, ParseWebConfigXml_ValidPerformanceConfig, TestSize.Level0)
{
    std::string configFilePath = "valid_performance.xml";
    EXPECT_NO_THROW(NWebConfigHelper::Instance().ParseWebConfigXml(configFilePath, initArgs));
}

/**
 * @tc.name: ParseWebConfigXml_ValidLTPOConfig
 * @tc.desc: ParseWebConfigXml.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NWebConfigHelperTest, ParseWebConfigXml_ValidLTPOConfig, TestSize.Level0)
{
    std::string configFilePath = "valid_ltpo.xml";
    EXPECT_NO_THROW(NWebConfigHelper::Instance().ParseWebConfigXml(configFilePath, initArgs));
}

/**
 * @tc.name: GetPerfConfig_ShouldReturnEmptyVector_WhenSettingNameNotExist
 * @tc.desc: GetPerfConfig.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NWebConfigHelperTest, GetPerfConfig_ShouldReturnEmptyVector_WhenSettingNameNotExist, TestSize.Level0)
{
    std::string settingName = "NonExistentSetting";
    std::vector<FrameRateSetting> result = NWebConfigHelper::Instance().GetPerfConfig(settingName);
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: GetPerfConfig_ShouldReturnNonEmptyVector_WhenSettingNameExist
 * @tc.desc: GetPerfConfig.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NWebConfigHelperTest, GetPerfConfig_ShouldReturnNonEmptyVector_WhenSettingNameExist, TestSize.Level0)
{
    std::string settingName = "ExistentSetting";
    NWebConfigHelper::Instance().ltpoConfig_[settingName] = {FrameRateSetting(30)};
    std::vector<FrameRateSetting> result = NWebConfigHelper::Instance().GetPerfConfig(settingName);
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(result[0].frameRate, 30);
}

/**
 * @tc.name: ParsePerfConfig_ShouldReturnEmptyString_WhenConfigNotFound
 * @tc.desc: ParsePerfConfig.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NWebConfigHelperTest, ParsePerfConfig_ShouldReturnEmptyString_WhenConfigNotFound, TestSize.Level0)
{
    std::string configNodeName = "non_existent_config";
    std::string argsNodeName = "non_existent_args";
    std::string result = NWebConfigHelper::Instance().ParsePerfConfig(configNodeName, argsNodeName);
    EXPECT_EQ(result, "");
}

/**
 * @tc.name: ParsePerfConfig_ShouldReturnValue_WhenConfigFound
 * @tc.desc: ParsePerfConfig.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NWebConfigHelperTest, ParsePerfConfig_ShouldReturnValue_WhenConfigFound, TestSize.Level0)
{
    std::string configNodeName = "existent_config";
    std::string argsNodeName = "existent_args";
    std::string expectedValue = "expected_value";
    NWebConfigHelper::Instance().perfConfig_[configNodeName + "/" + argsNodeName] = expectedValue;
    std::string result = NWebConfigHelper::Instance().ParsePerfConfig(configNodeName, argsNodeName);
    EXPECT_EQ(result, expectedValue);
}

/**
 * @tc.name: ParsePerfConfig_NullNode
 * @tc.desc: ParsePerfConfig.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NWebConfigHelperTest, ParsePerfConfig_NullNode, TestSize.Level0)
{
    xmlNodePtr node = nullptr;
    NWebConfigHelper::Instance().ParsePerfConfig(node);
    EXPECT_TRUE(NWebConfigHelper::Instance().perfConfig_.empty());
}

/**
 * @tc.name: ParsePerfConfig_CommentNode
 * @tc.desc: ParsePerfConfig.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NWebConfigHelperTest, ParsePerfConfig_CommentNode, TestSize.Level0)
{
    xmlNodePtr node = xmlNewNode(nullptr, "comment");
    NWebConfigHelper::Instance().ParsePerfConfig(node);
    EXPECT_TRUE(NWebConfigHelper::Instance().perfConfig_.empty());
    xmlFreeNode(node);
}

/**
 * @tc.name: ParsePerfConfig_ValidNode
 * @tc.desc: ParsePerfConfig.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NWebConfigHelperTest, ParsePerfConfig_ValidNode, TestSize.Level0)
 {
    xmlNodePtr node = xmlNewNode(nullptr, "node");
    xmlNodePtr childNode = xmlNewNode(nullptr, "childNode");
    EXPECT_NE(node, nullptr);
    EXPECT_NE(childNode, nullptr);
    xmlNodeAddContent(childNode, "value");
    xmlAddChild(node, childNode);
    NWebConfigHelper::Instance().ParsePerfConfig(node);
    EXPECT_EQ(hNWebConfigHelper::Instance().perfConfig_["node/childNode"], "value");
    xmlFreeNode(childNode);
    xmlFreeNode(node);
}

/**
 * @tc.name: ParsePerfConfig_InvalidChildNode
 * @tc.desc: ParsePerfConfig.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NWebConfigHelperTest, ParsePerfConfig_InvalidChildNode, TestSize.Level0)
 {
    xmlNodePtr node = xmlNewNode(nullptr, "node");
    xmlNodePtr childNode = xmlNewNode(nullptr, "comment");
    EXPECT_NE(node, nullptr);
    EXPECT_NE(childNode, nullptr);
    xmlAddChild(node, childNode);
    NWebConfigHelper::Instance().ParsePerfConfig(node);
    EXPECT_TRUE(NWebConfigHelper::Instance().perfConfig_.empty());
    xmlFreeNode(childNode);
    xmlFreeNode(node);
}

/**
 * @tc.name: ParsePerfConfig_NullContent
 * @tc.desc: ParsePerfConfig.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NWebConfigHelperTest, ParsePerfConfig_NullContent, TestSize.Level0)
 {
    xmlNodePtr node = xmlNewNode(nullptr, "node");
    xmlNodePtr childNode = xmlNewNode(nullptr, "childNode");
    EXPECT_NE(node, nullptr);
    EXPECT_NE(childNode, nullptr);
    xmlAddChild(node, childNode);
    NWebConfigHelper::Instance().ParsePerfConfig(node);
    EXPECT_TRUE(NWebConfigHelper::Instance().perfConfig_.empty());
    xmlFreeNode(childNode);
    xmlFreeNode(node);
 }

/**
 * @tc.name: ParseDeleteConfig_NullRootPtr
 * @tc.desc: ParseDeleteConfig.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NWebConfigHelperTest, ParseDeleteConfig_NullRootPtr, TestSize.Level0)
{
    xmlNodePtr rootPtr = nullptr;
    std::string result = NWebConfigHelper::Instance().ParseDeleteConfig(rootPtr, initArgs);
    EXPECT_EQ(result, "");
}

/**
 * @tc.name: ParseDeleteConfig_ValidNode
 * @tc.desc: ParseDeleteConfig.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NWebConfigHelperTest, ParseDeleteConfig_ValidNode, TestSize.Level0)
{
    xmlNodePtr rootPtr = xmlNewNode(nullptr, "valid");
    xmlNodePtr childNodePtr = xmlNewNode(nullptr, "child");
    EXPECT_NE(rootPtr, nullptr);
    EXPECT_NE(childNodePtr, nullptr);
    xmlAddChild(rootPtr, childNodePtr);
    xmlChar *content = xmlNodeGetContent(childNodePtr);
    xmlNodeSetContent(childNodePtr, content);
    xmlFree(content);
    NWebConfigHelper::Instance().ParseDeleteConfig(rootPtr, initArgs);
}

/**
 * @tc.name: ParseDeleteConfig_InvalidChildNode
 * @tc.desc: ParseDeleteConfig.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NWebConfigHelperTest, ParseDeleteConfig_InvalidChildNode, TestSize.Level0)
{
    xmlNodePtr rootPtr = xmlNewNode(nullptr, "valid");
    xmlNodePtr childNodePtr = xmlNewNode(nullptr, "invalid");
    EXPECT_NE(rootPtr, nullptr);
    EXPECT_NE(childNodePtr, nullptr);
    xmlAddChild(rootPtr, childNodePtr);
    NWebConfigHelper::Instance().ParseDeleteConfig(rootPtr, initArgs);
}

/**
 * @tc.name: ParseDeleteConfig_NullContent
 * @tc.desc: ParseDeleteConfig.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NWebConfigHelperTest, ParseDeleteConfig_NullContent, TestSize.Level0)
{
    xmlNodePtr rootPtr = xmlNewNode(nullptr, "valid");
    xmlNodePtr childNodePtr = xmlNewNode(nullptr, "child");
    EXPECT_NE(rootPtr, nullptr);
    EXPECT_NE(childNodePtr, nullptr);
    xmlAddChild(rootPtr, childNodePtr);
    NWebConfigHelper::Instance().ParseDeleteConfig(rootPtr, initArgs);
}

/**
 * @tc.name: ParseDeleteConfig_NotFoundConfig
 * @tc.desc: ParseDeleteConfig.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NWebConfigHelperTest, ParseDeleteConfig_NotFoundConfig, TestSize.Level0)
{
    xmlNodePtr rootPtr = xmlNewNode(nullptr, "valid");
    xmlNodePtr childNodePtr = xmlNewNode(nullptr, "child");
    EXPECT_NE(rootPtr, nullptr);
    EXPECT_NE(childNodePtr, nullptr);
    xmlAddChild(rootPtr, childNodePtr);
    xmlChar *content = xmlNodeGetContent(childNodePtr);
    xmlNodeSetContent(childNodePtr, content);
    xmlFree(content);
    NWebConfigHelper::Instance().ParseDeleteConfig(rootPtr, initArgs);
}

/**
 * @tc.name: ParseDeleteConfig_EmptyParam
 * @tc.desc: ParseDeleteConfig.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NWebConfigHelperTest, ParseDeleteConfig_EmptyParam, TestSize.Level0)
{
    xmlNodePtr rootPtr = xmlNewNode(nullptr, "valid");
    xmlNodePtr childNodePtr = xmlNewNode(nullptr, "child");
    EXPECT_NE(rootPtr, nullptr);
    EXPECT_NE(childNodePtr, nullptr);
    xmlAddChild(rootPtr, childNodePtr);
    xmlChar *content = xmlNodeGetContent(childNodePtr);
    xmlNodeSetContent(childNodePtr, content);
    xmlFree(content);
    NWebConfigHelper::Instance().ParseDeleteConfig(rootPtr, initArgs);
}

/**
 * @tc.name  : safeGetPropAsInt_ShouldReturnDefaultValue_WhenPropNotExist
 * @tc.number: OHOS_NWEB_001
 * @tc.desc  : Test safeGetPropAsInt function when the property does not exist.
 */
HWTEST_F(NWebConfigHelperTest, safeGetPropAsInt_ShouldReturnDefaultValue_WhenPropNotExist,
    testing::ext::TestSize.Level0)
{
    int defaultValue = 10;
    int result = NWebConfigHelper::Instance().safeGetPropAsInt(root_element,
      BAD_CAST "non_existent_prop", defaultValue);
    EXPECT_EQ(result, defaultValue);
}

/**
 * @tc.name  : safeGetPropAsInt_ShouldReturnPropValue_WhenPropExist
 * @tc.number: OHOS_NWEB_002
 * @tc.desc  : Test safeGetPropAsInt function when the property exists.
 */
HWTEST_F(NWebConfigHelperTest, safeGetPropAsInt_ShouldReturnPropValue_WhenPropExist, testing::ext::TestSize.Level0)
{
    xmlNewProp(rootElement, BAD_CAST "test_prop", BAD_CAST "20");
    int result = NWebConfigHelper::Instance().safeGetPropAsInt(rootElement, BAD_CAST "test_prop", 10);
    EXPECT_EQ(result, 20);
}

/**
 * @tc.name  : safeGetPropAsInt_ShouldReturnDefaultValue_WhenPropValueNotInt
 * @tc.number: OHOS_NWEB_003
 * @tc.desc  : Test safeGetPropAsInt function when the property value is not an integer.
 */
HWTEST_F(NWebConfigHelperTest, safeGetPropAsInt_ShouldReturnDefaultValue_WhenPropValueNotInt,
    testing::ext::TestSize.Level0)
{
    xmlNewProp(rootElement, BAD_CAST "test_prop", BAD_CAST "not_an_integer");
    int defaultValue = 10;
    int result = NWebConfigHelper::Instance().safeGetPropAsInt(rootElement, BAD_CAST "test_prop", defaultValue);
    EXPECT_EQ(result, defaultValue);
}

/**
 * @tc.name  : WriteConfigValueToSysPara_ShouldSetParameter_WhenConfigNameIsFlowBufferConfigMaxFdNumber
 * @tc.number: NWebConfigHelperTest_001
 * @tc.desc  : Test WriteConfigValueToSysPara method when configName is "flowBufferConfig/maxFdNumber"
 */
HWTEST_F(NWebConfigHelperTest,
    WriteConfigValueToSysPara_ShouldSetParameter_WhenConfigNameIsFlowBufferConfigMaxFdNumber, TestSize.Level0)
{
    std::string configName = "flowBufferConfig/maxFdNumber";
    std::string value = "1024";
    NWebConfigHelper::Instance().WriteConfigValueToSysPara(configName, value);
    std::string actualValue = OHOS::system::GetParameter("web.flowbuffer.maxfd");
    EXPECT_EQ(value, actualValue);
}

/**
 * @tc.name  : WriteConfigValueToSysPara_ShouldNotSetParameter_WhenConfigNameIsNotFlowBufferConfigMaxFdNumber
 * @tc.number: NWebConfigHelperTest_002
 * @tc.desc  : Test WriteConfigValueToSysPara method when configName is not "flowBufferConfig/maxFdNumber"
 */
HWTEST_F(NWebConfigHelperTest,
    WriteConfigValueToSysPara_ShouldNotSetParameter_WhenConfigNameIsNotFlowBufferConfigMaxFdNumber, TestSize.Level0)
{
    std::string configName = "someOtherConfig";
    std::string value = "1024";
    NWebConfigHelper::Instance().WriteConfigValueToSysPara(configName, value);
    std::string actualValue = OHOS::system::GetParameter("web.flowbuffer.maxfd");
    EXPECT_NE(value, actualValue);
}

/**
 * @tc.name  : ParseNWebLTPOConfig_ShouldHandleInvalidNode_WhenNodeIsNull
 * @tc.number: NWebConfigHelperTest_001
 * @tc.desc  : Test when node is null then ParseNWebLTPOConfig should handle it correctly
 */
HWTEST_F(NWebConfigHelperTest, ParseNWebLTPOConfig_ShouldHandleInvalidNode_WhenNodeIsNull, TestSize.Level0)
{
    xmlNodePtr nodePtr = nullptr;
    NWebConfigHelper::Instance().ParseNWebLTPOConfig(nodePtr);
}

/**
 * @tc.name  : ParseNWebLTPOConfig_ShouldHandleInvalidNode_WhenNodeIsComment
 * @tc.number: NWebConfigHelperTest_002
 * @tc.desc  : Test when node is a comment then ParseNWebLTPOConfig should handle it correctly
 */
HWTEST_F(NWebConfigHelperTest, ParseNWebLTPOConfig_ShouldHandleInvalidNode_WhenNodeIsComment, TestSize.Level0)
{
    xmlNodePtr nodePtr = xmlNewComment("This is a comment");
    NWebConfigHelper::Instance().ParseNWebLTPOConfig(nodePtr);
    xmlFreeNode(nodePtr);
}

/**
 * @tc.name  : ParseNWebLTPOConfig_ShouldHandleInvalidName_WhenNameIsNull
 * @tc.number: NWebConfigHelperTest_003
 * @tc.desc  : Test when name is null then ParseNWebLTPOConfig should handle it correctly
 */
HWTEST_F(NWebConfigHelperTest, ParseNWebLTPOConfig_ShouldHandleInvalidName_WhenNameIsNull, TestSize.Level0)
{
    xmlNodePtr nodePtr = xmlNewNode(nullptr, "testNode");
    NWebConfigHelper::Instance().ParseNWebLTPOConfig(nodePtr);
    xmlFreeNode(nodePtr);
}

/**
 * @tc.name  : ParseNWebLTPOConfig_ShouldHandleValidNode_WhenNameIsValid
 * @tc.number: NWebConfigHelperTest_004
 * @tc.desc  : Test when node and name are valid then ParseNWebLTPOConfig should handle it correctly
 */
HWTEST_F(NWebConfigHelperTest, ParseNWebLTPOConfig_ShouldHandleValidNode_WhenNameIsValid, TestSize.Level0)
{
    xmlNodePtr nodePtr = xmlNewNode(nullptr, "testNode");
    xmlNewProp(nodePtr, BAD_CAST(XML_ATTR_NAME), BAD_CAST("validName"));
    NWebConfigHelper::Instance().ParseNWebLTPOConfig(nodePtr);
    xmlFreeNode(nodePtr);
}

/**
 * @tc.name  : ParseNWebLTPOConfig_ShouldHandleInvalidDynamicNode_WhenDynamicNodeIsNull
 * @tc.number: NWebConfigHelperTest_005
 * @tc.desc  : Test when dynamic node is null then ParseNWebLTPOConfig should handle it correctly
 */
HWTEST_F(NWebConfigHelperTest, ParseNWebLTPOConfig_ShouldHandleInvalidDynamicNode_WhenDynamicNodeIsNull,
    TestSize.Level0)
{
    xmlNodePtr nodePtr = xmlNewNode(nullptr, "testNode");
    xmlNewProp(nodePtr, BAD_CAST(XML_ATTR_NAME), BAD_CAST("validName"));
    NWebConfigHelper::Instance().ParseNWebLTPOConfig(nodePtr);
    xmlFreeNode(nodePtr);
}

/**
 * @tc.name  : ParseNWebLTPOConfig_ShouldHandleInvalidDynamicNode_WhenDynamicNodeIsComment
 * @tc.number: NWebConfigHelperTest_006
 * @tc.desc  : Test when dynamic node is a comment then ParseNWebLTPOConfig should handle it correctly
 */
HWTEST_F(NWebConfigHelperTest, ParseNWebLTPOConfig_ShouldHandleInvalidDynamicNode_WhenDynamicNodeIsComment,
    TestSize.Level0)
{
    xmlNodePtr nodePtr = xmlNewNode(nullptr, "testNode");
    xmlNewProp(nodePtr, BAD_CAST(XML_ATTR_NAME), BAD_CAST("validName"));
    xmlNodePtr dynamicNodePtr = xmlNewComment("This is a comment");
    xmlAddChild(nodePtr, dynamicNodePtr);
    NWebConfigHelper::Instance().ParseNWebLTPOConfig(nodePtr);
    xmlFreeNode(nodePtr);
}

/**
 * @tc.name  : ParseNWebLTPOConfig_ShouldHandleValidDynamicNode_WhenDynamicNodeIsValid
 * @tc.number: NWebConfigHelperTest_007
 * @tc.desc  : Test when dynamic node and name are valid then ParseNWebLTPOConfig should handle it correctly
 */
HWTEST_F(NWebConfigHelperTest, ParseNWebLTPOConfig_ShouldHandleValidDynamicNode_WhenDynamicNodeIsValid, TestSize.Level0)
{
    xmlNodePtr nodePtr = xmlNewNode(nullptr, "testNode");
    xmlNewProp(nodePtr, BAD_CAST(XML_ATTR_NAME), BAD_CAST("validName"));
    xmlNodePtr dynamicNodePtr = xmlNewNode(nullptr, "testDynamicNode");
    xmlNewProp(dynamicNodePtr, BAD_CAST(XML_ATTR_MIN), BAD_CAST("10"));
    xmlNewProp(dynamicNodePtr, BAD_CAST(XML_ATTR_MAX), BAD_CAST("20"));
    xmlNewProp(dynamicNodePtr, BAD_CAST(XML_ATTR_FPS), BAD_CAST("30"));
    xmlAddChild(nodePtr, dynamicNodePtr);
    NWebConfigHelper::Instance().ParseNWebLTPOConfig(nodePtr);
    xmlFreeNode(nodePtr);
}

/**
 * @tc.name  : GetChildrenNode_ShouldReturnNode_WhenNodeExists
 * @tc.number: NWebConfigHelperTest_001
 * @tc.desc  : Test GetChildrenNode function when the node exists
 */
HWTEST_F(NWebConfigHelperTest, GetChildrenNode_ShouldReturnNode_WhenNodeExists, TestSize.Level0)
{
    xmlNodePtr rootNode = xmlNewNode(nullptr, BAD_CAST "root");
    xmlNodePtr childNode = xmlNewNode(nullptr, BAD_CAST "child");
    xmlAddChild(rootNode, childNode);
    xmlNodePtr resultNode = NWebConfigHelper::Instance().GetChildrenNode(rootNode, "child");
    EXPECT_EQ(resultNode, childNode);
    xmlFreeNode(rootNode);
    xmlFreeNode(childNode);
}

/**
 * @tc.name  : GetChildrenNode_ShouldReturnNull_WhenNodeNotExists
 * @tc.number: NWebConfigHelperTest_002
 * @tc.desc  : Test GetChildrenNode function when the node does not exist
 */
HWTEST_F(NWebConfigHelperTest, GetChildrenNode_ShouldReturnNull_WhenNodeNotExists, TestSize.Level0)
{
    xmlNodePtr rootNode = xmlNewNode(nullptr, BAD_CAST "root");
    xmlNodePtr childNode = xmlNewNode(nullptr, BAD_CAST "child");
    xmlAddChild(rootNode, childNode);
    xmlNodePtr resultNode = NWebConfigHelper::Instance().GetChildrenNode(rootNode, "non_existent_child");
    EXPECT_EQ(resultNode, nullptr);
    xmlFreeNode(rootNode);
    xmlFreeNode(childNode);
}

/**
 * @tc.name  : GetChildrenNode_ShouldReturnNull_WhenNodeIsNull
 * @tc.number: NWebConfigHelperTest_003
 * @tc.desc  : Test GetChildrenNode function when the node is null
 */
HWTEST_F(NWebConfigHelperTest, GetChildrenNode_ShouldReturnNull_WhenNodeIsNull, TestSize.Level0)
{
    xmlNodePtr resultNode = NWebConfigHelper::Instance().GetChildrenNode(nullptr, "child");
    EXPECT_EQ(resultNode, nullptr);
}

/**
 * @tc.name  : GetChildrenNode_ShouldReturnNull_WhenNodeNameIsEmpty
 * @tc.number: NWebConfigHelperTest_004
 * @tc.desc  : Test GetChildrenNode function when the node name is empty
 */
HWTEST_F(NWebConfigHelperTest, GetChildrenNode_ShouldReturnNull_WhenNodeNameIsEmpty, TestSize.Level0)
{
    xmlNodePtr rootNode = xmlNewNode(nullptr, BAD_CAST "root");
    xmlNodePtr childNode = xmlNewNode(nullptr, BAD_CAST "child");
    xmlAddChild(rootNode, childNode);
    xmlNodePtr resultNode = NWebConfigHelper::Instance().GetChildrenNode(rootNode, "");
    EXPECT_EQ(resultNode, nullptr);
    xmlFreeNode(rootNode);
    xmlFreeNode(childNode);
}

/**
 * @tc.name  : ReadConfig_ShouldHandleInvalidNode_WhenNodeIsNull
 * @tc.number: NWebConfigHelperTest_001
 * @tc.desc  : Test when node is null then ReadConfig should skip the node
 */
HWTEST_F(NWebConfigHelperTest, ReadConfig_ShouldHandleInvalidNode_WhenNodeIsNull, TestSize.Level0)
{
    rootElement->xmlChildrenNode = nullptr;
    NWebConfigHelper::Instance().ReadConfig(rootElement, initArgs);
    EXPECT_EQ(initArgs->GetArgs().size(), 0);
}

/**
 * @tc.name  : ReadConfig_ShouldHandleInvalidNode_WhenNodeIsComment
 * @tc.number: NWebConfigHelperTest_002
 * @tc.desc  : Test when node is a comment then ReadConfig should skip the node
 */
HWTEST_F(NWebConfigHelperTest, ReadConfig_ShouldHandleInvalidNode_WhenNodeIsComment, TestSize.Level0)
{
    rootElement->type = XML_COMMENT_NODE;
    NWebConfigHelper::Instance().ReadConfig(rootElement, initArgs);
    EXPECT_EQ(initArgs->GetArgs().size(), 0);
}

/**
 * @tc.name  : ReadConfig_ShouldHandleInvalidNode_WhenChildNodeIsNull
 * @tc.number: NWebConfigHelperTest_003
 * @tc.desc  : Test when child node is null then ReadConfig should skip the child node
 */
HWTEST_F(NWebConfigHelperTest, ReadConfig_ShouldHandleInvalidNode_WhenChildNodeIsNull, TestSize.Level0)
{
    rootElement->xmlChildrenNode = childNodePtr;
    childNodePtr->xmlChildrenNode = nullptr;
    NWebConfigHelper::Instance().ReadConfig(rootElement, initArgs);
    EXPECT_EQ(initArgs->GetArgs().size(), 0);
}

/**
 * @tc.name  : ReadConfig_ShouldHandleInvalidNode_WhenChildNodeIsComment
 * @tc.number: NWebConfigHelperTest_004
 * @tc.desc  : Test when child node is a comment then ReadConfig should skip the child node
 */
HWTEST_F(NWebConfigHelperTest, ReadConfig_ShouldHandleInvalidNode_WhenChildNodeIsComment, TestSize.Level0)
{
    rootElement->xmlChildrenNode = childNodePtr;
    childNodePtr->type = XML_COMMENT_NODE;
    NWebConfigHelper::Instance().ReadConfig(rootElement, initArgs);
    EXPECT_EQ(initArgs->GetArgs().size(), 0);
}

/**
 * @tc.name  : ReadConfig_ShouldHandleInvalidNode_WhenContentIsNull
 * @tc.number: NWebConfigHelperTest_005
 * @tc.desc  : Test when content is null then ReadConfig should skip the node
 */
HWTEST_F(NWebConfigHelperTest, ReadConfig_ShouldHandleInvalidNode_WhenContentIsNull, TestSize.Level0)
{
    rootElement->xmlChildrenNode = childNodePtr;
    childNodePtr->xmlChildrenNode = nullptr;
    NWebConfigHelper::Instance().ReadConfig(rootElement, initArgs);
    EXPECT_EQ(initArgs->GetArgs().size(), 0);
}

/**
 * @tc.name  : ReadConfig_ShouldHandleValidNode_WhenContentIsValid
 * @tc.number: NWebConfigHelperTest_006
 * @tc.desc  : Test when content is valid then ReadConfig should add the param to initArgs
 */
HWTEST_F(NWebConfigHelperTest, ReadConfig_ShouldHandleValidNode_WhenContentIsValid, TestSize.Level0)
{
    rootElement->xmlChildrenNode = childNodePtr;
    childNodePtr->xmlChildrenNode = nullptr;
    content = (xmlChar *) "valid_content";
    NWebConfigHelper::Instance().ReadConfig(rootElement, initArgs);
    EXPECT_GT(initArgs->GetArgs().size(), 0);
}

/**
 * @tc.name  : GetConfigPath_ShouldReturnSystemPath_WhenConfigPathIsInvalid
 * @tc.number: NWebConfigHelperTest_001
 * @tc.desc  : Test scenario for GetConfigPath when config path is invalid
 */
HWTEST_F(NWebConfigHelperTest, GetConfigPath_ShouldReturnSystemPath_WhenConfigPathIsInvalid, TestSize.Level0)
{
    std::string configFileName = "invalid_config_file";
    std::string expectedPath = "/system/" + configFileName;
    EXPECT_EQ(NWebConfigHelper::Instance().GetConfigPath(configFileName), expectedPath);
}

/**
 * @tc.name  : GetConfigPath_ShouldReturnEmptyPath_WhenConfigPathIsEmpty
 * @tc.number: NWebConfigHelperTest_003
 * @tc.desc  : Test scenario for GetConfigPath when config path is empty
 */
HWTEST_F(NWebConfigHelperTest, GetConfigPath_ShouldReturnEmptyPath_WhenConfigPathIsEmpty, TestSize.Level0)
{
    std::string configFileName = "";
    std::string expectedPath = "";
    EXPECT_EQ(NWebConfigHelper::Instance().GetConfigPath(configFileName), expectedPath);
}

/**
 * @tc.name  : NWebConfigHelper_ReadConfigIfNeeded_ShouldParseConfig_WhenPerfConfigEmpty
 * @tc.number: NWebConfigHelper_Test_001
 * @tc.desc  : Test that ReadConfigIfNeeded parses config when perfConfig is empty
 */
HWTEST_F(NWebConfigHelperTest, NWebConfigHelper_ReadConfigIfNeeded_ShouldParseConfig_WhenPerfConfigEmpty,
    TestSize.Level0)
{
    NWebConfigHelper::Instance().perfConfig_.clear();
    EXPECT_CALL(NWebConfigHelper::Instance(), ParseConfig(initArgs)).Times(1);
    NWebConfigHelper::Instance().ReadConfigIfNeeded();
}

/**
 * @tc.name  : NWebConfigHelper_ReadConfigIfNeeded_ShouldNotParseConfig_WhenPerfConfigNotEmpty
 * @tc.number: NWebConfigHelper_Test_002
 * @tc.desc  : Test that ReadConfigIfNeeded does not parse config when perfConfig is not empty
 */
HWTEST_F(NWebConfigHelperTest, NWebConfigHelper_ReadConfigIfNeeded_ShouldNotParseConfig_WhenPerfConfigNotEmpty,
    TestSize.Level0)
{
    NWebConfigHelper::Instance().perfConfig_.push_back("some_config");
    EXPECT_CALL(NWebConfigHelper::Instance(), ParseConfig(initArgs)).Times(0);
    NWebConfigHelper::Instance().ReadConfigIfNeeded();
}
} // NWebConfig
} // OHOS```