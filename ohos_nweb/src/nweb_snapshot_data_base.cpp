/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "nweb_snapshot_data_base.h"

#include "application_context.h"
#include "rdb_sql_utils.h"

#include "nweb_log.h"

using namespace OHOS::NativeRdb;

namespace OHOS::NWeb {
const int32_t RDB_VERSION = 1;
const std::string WEB_SNAPSHOT_DATABASE_FILE = "web_snapshot.db";

const std::string ID_COL = "_id";
const std::string SNAPSHOT_TABLE_NAME = "snapshot";
const std::string SNAPSHOT_URL_COL = "url";
const std::string WHOLE_SNAPSHOT_COL = "wholeSnapshotPath";
const std::string STATIC_SNAPSHOT_COL = "staticSnapshotPath";
const std::string SNAPSHOT_TIME_COL = "snapshotTime";
const int64_t MAXIMUM_TIME_LIMIT_MICRO_SECONDS = 1000LL * 1000 * 3600 * 24 * 7;

const std::string CREATE_TABLE = "CREATE TABLE " + SNAPSHOT_TABLE_NAME
    + " (" + ID_COL + " INTEGER PRIMARY KEY, "
    + SNAPSHOT_URL_COL + " TEXT, " + WHOLE_SNAPSHOT_COL + " TEXT, "
    + STATIC_SNAPSHOT_COL + " TEXT, " + SNAPSHOT_TIME_COL + " INTEGER, "
    + " UNIQUE (" + SNAPSHOT_URL_COL + ") ON CONFLICT REPLACE);";

const std::string WEB_PATH = "/web";

class SnapshotDataBaseRdbOpenCallback : public RdbOpenCallback {
public:
    int32_t OnCreate(RdbStore& rdbStore) override
    {
        return rdbStore.ExecuteSql(CREATE_TABLE);
    }

    int32_t OnUpgrade(RdbStore& rdbStore, int32_t currentVersion, int32_t targetVersion) override
    {
        return E_OK;
    }
};

NWebSnapshotDataBase::NWebSnapshotDataBase()
{
    SnapshotDataBaseRdbOpenCallback callback;
    auto context = AbilityRuntime::ApplicationContext::GetApplicationContext();
    if (context == nullptr) {
        WVLOG_E("NWebSnapshotDataBase get application context is nullptr");
        return;
    }

    std::string dataBaseDir = context->GetCacheDir() + WEB_PATH;
    if (access(dataBaseDir.c_str(), F_OK) != 0) {
        WVLOG_E("NWebSnapshotDataBase access cache dir failed");
        return;
    }

    int32_t errCode = E_OK;
    RdbStoreConfig config("");
    config.SetPath(RdbSqlUtils::GetDefaultDatabasePath(dataBaseDir, WEB_SNAPSHOT_DATABASE_FILE, errCode));
    config.SetBundleName(context->GetBundleName());
    config.SetName(WEB_SNAPSHOT_DATABASE_FILE);
    config.SetArea(context->GetArea());

    rdbStore_ = RdbHelper::GetRdbStore(config, RDB_VERSION, callback, errCode);
    WVLOG_I("web snapshot database create rdb store, errCode = %{public}d", errCode);
}

NWebSnapshotDataBase& NWebSnapshotDataBase::Instance()
{
    static NWebSnapshotDataBase instance;
    return instance;
}

SnapshotDataItem NWebSnapshotDataBase::GetSnapshotDataItem(const std::string& url)
{
    SnapshotDataItem data;
    if (rdbStore_ == nullptr) {
        WVLOG_E("web snapshot database rdb store is nullptr");
        return data;
    }

    std::vector<std::string> columns;
    AbsRdbPredicates disAbsPred(SNAPSHOT_TABLE_NAME);
    disAbsPred.EqualTo(SNAPSHOT_URL_COL, url);
    auto resultSet = rdbStore_->Query(disAbsPred, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != E_OK) {
        WVLOG_E("web snapshot database get data failed");
        return data;
    }

    int64_t snapshotTime = 0;
    int32_t snapshotTimeColumnIndex;
    resultSet->GetColumnIndex(SNAPSHOT_TIME_COL, snapshotTimeColumnIndex);
    resultSet->GetLong(snapshotTimeColumnIndex, snapshotTime);

    auto currentTimeStamp = std::chrono::system_clock::now().time_since_epoch();
    int64_t currentTime = std::chrono::duration_cast<std::chrono::microseconds>(currentTimeStamp).count();
    if (currentTime - MAXIMUM_TIME_LIMIT_MICRO_SECONDS >= snapshotTime) {
        WVLOG_E("web snapshot database get data timeout");
        return data;
    }

    int32_t wholePathColumnIndex;
    resultSet->GetColumnIndex(WHOLE_SNAPSHOT_COL, wholePathColumnIndex);
    resultSet->GetString(wholePathColumnIndex, data.wholePath);

    int32_t staticPathColumnIndex;
    resultSet->GetColumnIndex(STATIC_SNAPSHOT_COL, staticPathColumnIndex);
    resultSet->GetString(staticPathColumnIndex, data.staticPath);
    return data;
}
} // namespace OHOS::NWeb
