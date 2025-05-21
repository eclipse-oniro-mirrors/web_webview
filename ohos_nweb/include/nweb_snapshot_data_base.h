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

#ifndef NWEB_SNAPSHOT_DATA_BASE_H
#define NWEB_SNAPSHOT_DATA_BASE_H

#include <string>
#include <unordered_map>
#include <vector>

#include "rdb_helper.h"

#include "nweb_export.h"

namespace OHOS::NWeb {
struct SnapshotDataItem {
    std::string wholePath;
    std::string staticPath;
};

class OHOS_NWEB_EXPORT NWebSnapshotDataBase {
public:
    static NWebSnapshotDataBase& Instance();
    ~NWebSnapshotDataBase() = default;
    SnapshotDataItem GetSnapshotDataItem(const std::string& url);

private:
    NWebSnapshotDataBase();
    NWebSnapshotDataBase(const NWebSnapshotDataBase& other) = delete;
    NWebSnapshotDataBase& operator=(const NWebSnapshotDataBase& other) = delete;

    std::shared_ptr<OHOS::NativeRdb::RdbStore> rdbStore_;
};
} // namespace OHOS

#endif // NWEB_SNAPSHOT_DATA_BASE_H
