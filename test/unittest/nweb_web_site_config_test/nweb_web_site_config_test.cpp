/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "nweb_web_site_config_params.h"
#include "nweb_web_site_config_result.h"
#include "nweb_web_site_config_callback.h"

#include "ark_web_web_site_config_result_impl.h"
#include "ark_web_web_site_config_callback_impl.h"
#include "ark_web_web_site_config_params_wrapper.h"

#include "base/include/ark_web_types.h"

using namespace testing;
using namespace OHOS::NWeb;
using namespace OHOS::ArkWeb;

namespace {

const std::string TEST_USER_AGENT = "TestCustomUA/1.0";
const int32_t TEST_VIEWPORT_WIDTH = 360;
const std::string TEST_URL = "https://www.example.com/page";
const std::string TEST_TOP_FRAME_URL = "https://www.example.com";
const std::string TEST_REFERRER = "https://ref.example.com";
const int32_t TEST_PAGE_TRANSITION = 5;

}  // namespace

// ---- Mock business-layer implementations ----

class MockNWebWebSiteConfigResult : public NWebWebSiteConfigResult {
public:
    MOCK_METHOD(std::string, UserAgent, (), (override));
    MOCK_METHOD(int32_t, ViewportWidth, (), (override));
};

class MockNWebWebSiteConfigCallback : public NWebWebSiteConfigCallback {
public:
    MOCK_METHOD(std::shared_ptr<NWebWebSiteConfigResult>, QueryWebSiteConfig,
                (std::shared_ptr<NWebWebSiteConfigParams>), (override));
};

// ---- Fake glue-layer ArkWebWebSiteConfigParams for wrapper tests ----

class FakeArkWebWebSiteConfigParams : public ArkWebWebSiteConfigParams {
public:
    FakeArkWebWebSiteConfigParams(const std::string& url, int32_t source, bool isMainFrame,
                                  const std::string& topFrameUrl,
                                  const std::vector<std::string>& redirectChain,
                                  const std::string& referrer, int32_t pageTransition)
        : url_(ArkWebStringClassToStruct(url)), source_(source), isMainFrame_(isMainFrame),
          topFrameUrl_(ArkWebStringClassToStruct(topFrameUrl)),
          redirectChain_(ArkWebStringVectorClassToStruct(redirectChain)),
          referrer_(ArkWebStringClassToStruct(referrer)),
          pageTransition_(pageTransition) {}

    ~FakeArkWebWebSiteConfigParams() override
    {
        ArkWebStringStructRelease(url_);
        ArkWebStringStructRelease(topFrameUrl_);
        ArkWebStringStructRelease(referrer_);
        ArkWebStringVectorStructRelease(redirectChain_);
    }

    ArkWebString Url() override { return ArkWebStringClassToStruct(ArkWebStringStructToClass(url_)); }
    int32_t Source() override { return source_; }
    bool IsMainFrame() override { return isMainFrame_; }
    ArkWebString TopFrameUrl() override { return ArkWebStringClassToStruct(ArkWebStringStructToClass(topFrameUrl_)); }
    ArkWebStringVector RedirectChain() override
    {
        auto vec = ArkWebStringVectorStructToClass(redirectChain_);
        return ArkWebStringVectorClassToStruct(vec);
    }
    ArkWebString Referrer() override { return ArkWebStringClassToStruct(ArkWebStringStructToClass(referrer_)); }
    int32_t PageTransition() override { return pageTransition_; }
    bool HasIsMainFrame() override { return hasIsMainFrame_; }
    bool HasTopFrameUrl() override { return hasTopFrameUrl_; }
    bool HasRedirectChain() override { return hasRedirectChain_; }
    bool HasReferrer() override { return hasReferrer_; }
    bool HasPageTransition() override { return hasPageTransition_; }

    void SetHasAll(bool has) {
        hasIsMainFrame_ = has;
        hasTopFrameUrl_ = has;
        hasRedirectChain_ = has;
        hasReferrer_ = has;
        hasPageTransition_ = has;
    }

    void IncreRef() const override {}
    void DecreRef() const override {}

private:
    ArkWebString url_;
    int32_t source_;
    bool isMainFrame_;
    ArkWebString topFrameUrl_;
    ArkWebStringVector redirectChain_;
    ArkWebString referrer_;
    int32_t pageTransition_;
    bool hasIsMainFrame_ = true;
    bool hasTopFrameUrl_ = true;
    bool hasRedirectChain_ = true;
    bool hasReferrer_ = true;
    bool hasPageTransition_ = true;
};

// ================== ArkWebWebSiteConfigResultImpl tests ==================
// ArkWebWebSiteConfigResultImpl is the webview-side bridge that implements
// ArkWebWebSiteConfigResult (glue interface) by delegating to a
// shared_ptr<NWebWebSiteConfigResult> (business interface).

class WebSiteConfigResultImplTest : public Test {};

/**
 * @tc.name: WebSiteConfigResultImplTest_UserAgent_001
 * @tc.desc: Verify UserAgent conversion to ArkWebString.
 * @tc.type: Func
 */
TEST_F(WebSiteConfigResultImplTest, UserAgent_001)
{
    auto mock = std::make_shared<MockNWebWebSiteConfigResult>();
    EXPECT_CALL(*mock, UserAgent()).WillRepeatedly(Return(TEST_USER_AGENT));
    ArkWebWebSiteConfigResultImpl impl(mock);
    ArkWebString str = impl.UserAgent();
    std::string result = ArkWebStringStructToClass(str);
    ArkWebStringStructRelease(str);
    EXPECT_EQ(result, TEST_USER_AGENT);
}

/**
 * @tc.name: WebSiteConfigResultImplTest_ViewportWidth_001
 * @tc.desc: Verify ViewportWidth delegates directly.
 * @tc.type: Func
 */
TEST_F(WebSiteConfigResultImplTest, ViewportWidth_001)
{
    auto mock = std::make_shared<MockNWebWebSiteConfigResult>();
    EXPECT_CALL(*mock, ViewportWidth())
        .WillRepeatedly(Return(TEST_VIEWPORT_WIDTH));
    ArkWebWebSiteConfigResultImpl impl(mock);
    EXPECT_EQ(impl.ViewportWidth(), TEST_VIEWPORT_WIDTH);
}

// ================== ArkWebWebSiteConfigCallbackImpl tests ==================
// ArkWebWebSiteConfigCallbackImpl is the webview-side bridge that implements
// ArkWebWebSiteConfigCallback (glue interface) by delegating to a
// shared_ptr<NWebWebSiteConfigCallback> (business interface).

class WebSiteConfigCallbackImplTest : public Test {};

/**
 * @tc.name: WebSiteConfigCallbackImplTest_Query_NullParams_001
 * @tc.desc: Verify QueryWebSiteConfig returns nullptr when params is null,
 *           without invoking the business-layer callback.
 * @tc.type: Func
 */
TEST_F(WebSiteConfigCallbackImplTest, Query_NullParams_001)
{
    auto mock_callback = std::make_shared<MockNWebWebSiteConfigCallback>();
    EXPECT_CALL(*mock_callback, QueryWebSiteConfig(_)).Times(0);

    ArkWebWebSiteConfigCallbackImpl impl(mock_callback);
    ArkWebRefPtr<ArkWebWebSiteConfigResult> ark_result =
        impl.QueryWebSiteConfig(nullptr);
    EXPECT_EQ(ark_result.get(), nullptr);
}

/**
 * @tc.name: WebSiteConfigCallbackImplTest_Query_NormalResult_002
 * @tc.desc: Verify QueryWebSiteConfig wraps a non-null business-layer result
 *           into ArkWebRefPtr<ArkWebWebSiteConfigResultImpl>.
 * @tc.type: Func
 */
TEST_F(WebSiteConfigCallbackImplTest, Query_NormalResult_002)
{
    auto mock_result = std::make_shared<MockNWebWebSiteConfigResult>();
    EXPECT_CALL(*mock_result, UserAgent()).WillRepeatedly(Return(TEST_USER_AGENT));
    EXPECT_CALL(*mock_result, ViewportWidth()).WillRepeatedly(Return(TEST_VIEWPORT_WIDTH));

    auto mock_callback = std::make_shared<MockNWebWebSiteConfigCallback>();
    EXPECT_CALL(*mock_callback, QueryWebSiteConfig(_))
        .WillOnce(Return(mock_result));

    ArkWebWebSiteConfigCallbackImpl impl(mock_callback);
    ArkWebRefPtr<ArkWebWebSiteConfigResult> ark_result =
        impl.QueryWebSiteConfig(nullptr);
    ASSERT_NE(ark_result.get(), nullptr);
    ArkWebString ua = ark_result->UserAgent();
    std::string ua_str = ArkWebStringStructToClass(ua);
    ArkWebStringStructRelease(ua);
    EXPECT_EQ(ua_str, TEST_USER_AGENT);
    EXPECT_EQ(ark_result->ViewportWidth(), TEST_VIEWPORT_WIDTH);
}

/**
 * @tc.name: WebSiteConfigCallbackImplTest_Query_NullResult_003
 * @tc.desc: Verify QueryWebSiteConfig returns nullptr when the business-layer
 *           callback returns a null result.
 * @tc.type: Func
 */
TEST_F(WebSiteConfigCallbackImplTest, Query_NullResult_003)
{
    auto mock_callback = std::make_shared<MockNWebWebSiteConfigCallback>();
    EXPECT_CALL(*mock_callback, QueryWebSiteConfig(_))
        .WillOnce(Return(nullptr));

    ArkWebWebSiteConfigCallbackImpl impl(mock_callback);
    ArkWebRefPtr<ArkWebWebSiteConfigResult> ark_result =
        impl.QueryWebSiteConfig(nullptr);
    EXPECT_EQ(ark_result.get(), nullptr);
}

// ================== ArkWebWebSiteConfigParamsWrapper tests ==================
// ArkWebWebSiteConfigParamsWrapper is the webview-side bridge that implements
// NWebWebSiteConfigParams (business interface) by delegating to a
// ArkWebRefPtr<ArkWebWebSiteConfigParams> (glue interface).

class WebSiteConfigParamsWrapperTest : public Test {};

/**
 * @tc.name: WebSiteConfigParamsWrapperTest_AllFields_001
 * @tc.desc: Verify all field conversions from ArkWeb glue types to NWeb types.
 * @tc.type: Func
 */
TEST_F(WebSiteConfigParamsWrapperTest, AllFields_001)
{
    auto* fake = new FakeArkWebWebSiteConfigParams(
        TEST_URL, static_cast<int32_t>(NWebWebSiteSource::WEB_PAGE), true,
        TEST_TOP_FRAME_URL, std::vector<std::string>{"https://a.com", "https://b.com"},
        TEST_REFERRER, TEST_PAGE_TRANSITION);

    ArkWebRefPtr<ArkWebWebSiteConfigParams> refptr(fake);
    ArkWebWebSiteConfigParamsWrapper wrapper(refptr);

    EXPECT_EQ(wrapper.Url(), TEST_URL);
    EXPECT_EQ(wrapper.Source(), NWebWebSiteSource::WEB_PAGE);
    EXPECT_TRUE(wrapper.IsMainFrame());
    EXPECT_EQ(wrapper.TopFrameUrl(), TEST_TOP_FRAME_URL);

    auto chain_result = wrapper.RedirectChain();
    ASSERT_EQ(chain_result.size(), 2UL);
    EXPECT_EQ(chain_result[0], "https://a.com");
    EXPECT_EQ(chain_result[1], "https://b.com");

    EXPECT_EQ(wrapper.Referrer(), TEST_REFERRER);
    EXPECT_EQ(wrapper.PageTransition(), TEST_PAGE_TRANSITION);
}

/**
 * @tc.name: WebSiteConfigParamsWrapperTest_EmptyFields_002
 * @tc.desc: Verify wrapper handles empty strings and empty redirect chain.
 * @tc.type: Func
 */
TEST_F(WebSiteConfigParamsWrapperTest, EmptyFields_002)
{
    auto* fake = new FakeArkWebWebSiteConfigParams(
        std::string(), static_cast<int32_t>(NWebWebSiteSource::OTHER), false,
        std::string(), std::vector<std::string>(), std::string(), 0);

    ArkWebRefPtr<ArkWebWebSiteConfigParams> refptr(fake);
    ArkWebWebSiteConfigParamsWrapper wrapper(refptr);

    EXPECT_TRUE(wrapper.Url().empty());
    EXPECT_FALSE(wrapper.IsMainFrame());
    EXPECT_TRUE(wrapper.TopFrameUrl().empty());
    EXPECT_TRUE(wrapper.RedirectChain().empty());
    EXPECT_TRUE(wrapper.Referrer().empty());
    EXPECT_EQ(wrapper.PageTransition(), 0);
}

/**
 * @tc.name: WebSiteConfigParamsWrapperTest_OptionalFieldsAbsent_003
 * @tc.desc: Verify Has*() returns false when optional fields are absent
 *           (static global callback scenario).
 * @tc.type: Func
 */
TEST_F(WebSiteConfigParamsWrapperTest, OptionalFieldsAbsent_003)
{
    auto* fake = new FakeArkWebWebSiteConfigParams(
        TEST_URL, static_cast<int32_t>(NWebWebSiteSource::WEB_PAGE), false,
        std::string(), std::vector<std::string>(), std::string(), 0);
    fake->SetHasAll(false);

    ArkWebRefPtr<ArkWebWebSiteConfigParams> refptr(fake);
    ArkWebWebSiteConfigParamsWrapper wrapper(refptr);

    EXPECT_FALSE(wrapper.HasIsMainFrame());
    EXPECT_FALSE(wrapper.HasTopFrameUrl());
    EXPECT_FALSE(wrapper.HasRedirectChain());
    EXPECT_FALSE(wrapper.HasReferrer());
    EXPECT_FALSE(wrapper.HasPageTransition());
}

/**
 * @tc.name: WebSiteConfigParamsWrapperTest_OptionalFieldsPresent_004
 * @tc.desc: Verify Has*() returns true when optional fields are present
 *           (instance-level callback scenario).
 * @tc.type: Func
 */
TEST_F(WebSiteConfigParamsWrapperTest, OptionalFieldsPresent_004)
{
    auto* fake = new FakeArkWebWebSiteConfigParams(
        TEST_URL, static_cast<int32_t>(NWebWebSiteSource::WEB_PAGE), true,
        TEST_TOP_FRAME_URL, std::vector<std::string>{"https://a.com"},
        TEST_REFERRER, TEST_PAGE_TRANSITION);
    // Has*() defaults to true in FakeArkWebWebSiteConfigParams

    ArkWebRefPtr<ArkWebWebSiteConfigParams> refptr(fake);
    ArkWebWebSiteConfigParamsWrapper wrapper(refptr);

    EXPECT_TRUE(wrapper.HasIsMainFrame());
    EXPECT_TRUE(wrapper.HasTopFrameUrl());
    EXPECT_TRUE(wrapper.HasRedirectChain());
    EXPECT_TRUE(wrapper.HasReferrer());
    EXPECT_TRUE(wrapper.HasPageTransition());
}
