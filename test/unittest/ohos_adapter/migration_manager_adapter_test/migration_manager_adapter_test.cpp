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
#include <cstring>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <map>
#include <mutex>

#define private public
#include "ability_manager_client.h"
#include "iservice_registry.h"
#include "migration_manager_adapter_impl.h"
#include "system_ability.h"
#include "system_ability_definition.h"
#undef private

#include "message_parcel.h"
#include "string_ex.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace {
int32_t g_sendRequestRet = ERR_OK;
std::string g_replyData;
ErrCode g_connectAbilityRet = -1;
} // namespace

namespace AAFwk {
ErrCode AbilityManagerClient::ConnectAbility(const Want& want, sptr<IAbilityConnection> connect, int32_t userId)
{
    return g_connectAbilityRet;
}
} // namespace AAFwk

namespace NWeb {

class MockRemoteObject : public IRemoteObject {
public:
    MockRemoteObject() : IRemoteObject { u"MockRemoteObject" } {}

    ~MockRemoteObject() {}

    int32_t GetObjectRefCount() override
    {
        return 0;
    }

    int SendRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override
    {
        if (g_sendRequestRet != ERR_OK) {
            return g_sendRequestRet;
        }
        reply.WriteString16(Str8ToStr16(g_replyData));
        return ERR_OK;
    }

    bool Marshalling(Parcel& parcel) const override
    {
        return true;
    }

    bool AddDeathRecipient(const sptr<DeathRecipient>& recipient) override
    {
        return true;
    }

    bool RemoveDeathRecipient(const sptr<DeathRecipient>& recipient) override
    {
        return true;
    }

    int Dump(int fd, const std::vector<std::u16string>& args) override
    {
        return 0;
    }
};

class MigrationListenerAdapterTest : public MigrationListenerAdapter {
public:
    MigrationListenerAdapterTest() = default;

    virtual ~MigrationListenerAdapterTest() = default;

    void OnMigrationReply(int32_t errorCode, int32_t succussCount, const std::vector<int32_t>& errorIndex,
        const std::vector<int32_t>& codeList) override
    {}
};

class MigrationManagerAdapterlmplTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void MigrationManagerAdapterlmplTest::SetUpTestCase(void) {}

void MigrationManagerAdapterlmplTest::TearDownTestCase(void) {}

void MigrationManagerAdapterlmplTest::SetUp(void) {}

void MigrationManagerAdapterlmplTest::TearDown(void) {}

/**
 * @tc.name: MigrationManagerAdapterlmplTest_001
 * @tc.desc: MigrationListenAdapter Func
 * @tc.type: FUNC
 * @tc.require: AR000I7I57
 */
HWTEST_F(MigrationManagerAdapterlmplTest, MigrationManagerAdapterlmplTest_001, TestSize.Level1)
{
    std::shared_ptr<MigrationListenerAdapter> listener = std::make_shared<MigrationListenerAdapterTest>();
    std::unique_ptr<MigrationManagerAdapterImpl::MigrationListenerAdapterImpl> migrationListener =
        std::make_unique<MigrationManagerAdapterImpl::MigrationListenerAdapterImpl>(listener);
    std::vector<int32_t> vec(0);
    migrationListener->SetJsonData("JsonTest");
    migrationListener->SetInterfaceToken("InterfaceTokenTest");
    migrationListener->OnMigrationReply(0, 0, vec, vec);
    EXPECT_NE(migrationListener, nullptr);
}

/**
 * @tc.name: MigrationManagerAdapterlmplTest_002
 * @tc.desc: MigrationManagerAdapterlmpl SendMigrationRequest.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MigrationManagerAdapterlmplTest, MigrationManagerAdapterlmplTest_002, TestSize.Level1)
{
    std::shared_ptr<MigrationManagerAdapterImpl> migrationManagermpl = std::make_shared<MigrationManagerAdapterImpl>();
    std::shared_ptr<MigrationListenerAdapter> listener = std::make_shared<MigrationListenerAdapterTest>();
    EXPECT_NE(migrationManagermpl, nullptr);
    EXPECT_NE(listener, nullptr);
    EXPECT_EQ(migrationManagermpl->RegisterMigrationListener(listener), 0);
    migrationManagermpl->SetMigrationParam("", "", "");
    EXPECT_FALSE(migrationManagermpl->SendMigrationRequest(std::make_shared<std::string>("")));
}

/**
 *
 * @tc.name: MigrationManagerAdapterlmplTest_003
 * @tc.desc: MigrationManagerAdapterlmpl OnAbilityConnectDone
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MigrationManagerAdapterlmplTest, MigrationManagerAdapterlmplTest_003, TestSize.Level1)
{
    std::shared_ptr<MigrationManagerAdapterImpl> migrationManagermpl = std::make_shared<MigrationManagerAdapterImpl>();
    std::shared_ptr<MigrationListenerAdapter> listener = std::make_shared<MigrationListenerAdapterTest>();
    std::unique_ptr<MigrationManagerAdapterImpl::MigrationListenerAdapterImpl> migrationListener =
        std::make_unique<MigrationManagerAdapterImpl::MigrationListenerAdapterImpl>(listener);
    EXPECT_EQ(migrationManagermpl->RegisterMigrationListener(listener), 0);

    const AppExecFwk::ElementName elementName("aaa", "bbb", "ccc");
    OHOS::sptr<OHOS::IRemoteObject> sp(nullptr);
    migrationListener->OnAbilityConnectDone(elementName, sp, 0);

    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sp = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    EXPECT_NE(sp, nullptr);
    migrationListener->OnAbilityConnectDone(elementName, sp, 0);
    EXPECT_TRUE(migrationManagermpl->SendMigrationRequest(std::make_shared<std::string>("")));

    migrationListener->OnAbilityDisconnectDone(elementName, 0);
    EXPECT_FALSE(migrationManagermpl->SendMigrationRequest(std::make_shared<std::string>("")));
}

/**
 * @tc.name: MigrationManagerAdapterlmplTest_004
 * @tc.desc: OnMigrationReply with null listener and SetMigrationParam without register.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MigrationManagerAdapterlmplTest, MigrationManagerAdapterlmplTest_004, TestSize.Level1)
{
    std::unique_ptr<MigrationManagerAdapterImpl::MigrationListenerAdapterImpl> migrationListener =
        std::make_unique<MigrationManagerAdapterImpl::MigrationListenerAdapterImpl>(nullptr);
    std::vector<int32_t> vec(0);
    migrationListener->OnMigrationReply(0, 0, vec, vec);
    EXPECT_NE(migrationListener, nullptr);

    std::shared_ptr<MigrationManagerAdapterImpl> migrationManagermpl = std::make_shared<MigrationManagerAdapterImpl>();
    migrationManagermpl->SetMigrationParam("bundle", "ability", "token");
    EXPECT_EQ(migrationManagermpl->callback_, nullptr);
}

/**
 * @tc.name: MigrationManagerAdapterlmplTest_005
 * @tc.desc: SendMigrationRequest with null jsonData and null callback.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MigrationManagerAdapterlmplTest, MigrationManagerAdapterlmplTest_005, TestSize.Level1)
{
    std::shared_ptr<MigrationManagerAdapterImpl> migrationManagermpl = std::make_shared<MigrationManagerAdapterImpl>();
    EXPECT_FALSE(migrationManagermpl->SendMigrationRequest(nullptr));

    MigrationManagerAdapterImpl::isConnectSystemUI_.store(false);
    g_connectAbilityRet = ERR_OK;
    EXPECT_TRUE(migrationManagermpl->SendMigrationRequest(std::make_shared<std::string>("data")));
    g_connectAbilityRet = -1;
    EXPECT_FALSE(migrationManagermpl->SendMigrationRequest(std::make_shared<std::string>("data")));

    // connected to SystemUI but callback is nullptr.
    MigrationManagerAdapterImpl::isConnectSystemUI_.store(true);
    EXPECT_FALSE(migrationManagermpl->SendMigrationRequest(std::make_shared<std::string>("data")));
    MigrationManagerAdapterImpl::isConnectSystemUI_.store(false);
}

/**
 * @tc.name: MigrationManagerAdapterlmplTest_006
 * @tc.desc: RegisterMigrationListener with null listener.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MigrationManagerAdapterlmplTest, MigrationManagerAdapterlmplTest_006, TestSize.Level1)
{
    std::shared_ptr<MigrationManagerAdapterImpl> migrationManagermpl = std::make_shared<MigrationManagerAdapterImpl>();
    EXPECT_EQ(migrationManagermpl->RegisterMigrationListener(nullptr), 0);
}

/**
 * @tc.name: MigrationManagerAdapterlmplTest_007
 * @tc.desc: OnAbilityConnectDone SendRequest failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MigrationManagerAdapterlmplTest, MigrationManagerAdapterlmplTest_007, TestSize.Level1)
{
    std::shared_ptr<MigrationListenerAdapter> listener = std::make_shared<MigrationListenerAdapterTest>();
    std::unique_ptr<MigrationManagerAdapterImpl::MigrationListenerAdapterImpl> migrationListener =
        std::make_unique<MigrationManagerAdapterImpl::MigrationListenerAdapterImpl>(listener);
    const AppExecFwk::ElementName elementName("aaa", "bbb", "ccc");
    OHOS::sptr<OHOS::IRemoteObject> sp(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(sp, nullptr);
    g_sendRequestRet = -1;
    migrationListener->OnAbilityConnectDone(elementName, sp, 0);
    g_sendRequestRet = ERR_OK;
}

/**
 * @tc.name: MigrationManagerAdapterlmplTest_008
 * @tc.desc: OnAbilityConnectDone reply json parse branches.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MigrationManagerAdapterlmplTest, MigrationManagerAdapterlmplTest_008, TestSize.Level1)
{
    std::shared_ptr<MigrationListenerAdapter> listener = std::make_shared<MigrationListenerAdapterTest>();
    std::unique_ptr<MigrationManagerAdapterImpl::MigrationListenerAdapterImpl> migrationListener =
        std::make_unique<MigrationManagerAdapterImpl::MigrationListenerAdapterImpl>(listener);
    const AppExecFwk::ElementName elementName("aaa", "bbb", "ccc");
    OHOS::sptr<OHOS::IRemoteObject> sp(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(sp, nullptr);
    g_sendRequestRet = ERR_OK;

    // invalid json: parse discarded.
    g_replyData = "not a json{{";
    migrationListener->OnAbilityConnectDone(elementName, sp, 0);

    // empty json: no fields contained.
    g_replyData = "{}";
    migrationListener->OnAbilityConnectDone(elementName, sp, 0);

    // fields with wrong types and empty error list.
    g_replyData = R"({"code":"x","errorList":[],"successCount":"y"})";
    migrationListener->OnAbilityConnectDone(elementName, sp, 0);

    // full valid reply: error items with complete/partial keys.
    g_replyData = R"({"code":0,"errorList":[{"code":1,"index":0},{"code":2},{"index":3}],"successCount":5})";
    migrationListener->OnAbilityConnectDone(elementName, sp, 0);
}

} // namespace NWeb
} // namespace OHOS
