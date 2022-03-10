// Copyright (c) 2022 Huawei Device Co., Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NWEB_VALUE_H_
#define NWEB_VALUE_H_

#include <iostream>
#include <string>
#include "nweb_export.h"

namespace OHOS::NWeb {
    union data_union {
        int n;
        double f;
        bool b;
    };

class OHOS_NWEB_EXPORT NWebValue {
public:
    enum class Type : unsigned char {
        NONE = 0,
        BOOLEAN,
        INTEGER,
        DOUBLE,
        STRING,
        BINARY,
        DICTIONARY,
        LIST
    };

    NWebValue(Type type) : type_(type) {}

    ~NWebValue() = default;

    bool GetBoolean() { return data_.b; }

    void SetBoolean(bool b) { data_.b = b; }

    void SetString(std::string str) { str_ = str; }

    std::string GetString() { return str_; }

    void SetDouble(double dou) { data_.f = dou; }

    double GetDouble() { return data_.f; }

    void SetInt(int num) { data_.n = num; }

    int GetInt() { return data_.n; }

    void SetJsonString(std::string json_string) { str_json_ = json_string; }

    std::string GetJsonString() { return str_json_; }

    Type GetType() { return type_; }

    void SetType(Type type) { type_ = type; }

    int error_ = 0;

private:
    Type type_ = Type::NONE;
    data_union data_;
    std::string str_;
    std::string str_json_;
};
}

#endif  // NWEB_VALUE_H_
