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

#include "webview_javascript_result_callback.h"

namespace OHOS::NWeb {
namespace {
void ParseArrayNwebValue2NapiValue(napi_env env, const std::shared_ptr<NWebValue>& value, napi_value& napiValue,
    WebviewJavaScriptResultCallBack::ObjectMap& objectsMap);
void ParseDictionaryNwebValue2NapiValue(napi_env env, const std::shared_ptr<NWebValue>& value, napi_value& napiValue,
    WebviewJavaScriptResultCallBack::ObjectMap& objectsMap);
void ParseDictionaryNapiValue2NwebValue(
    napi_env env, napi_value& value, std::shared_ptr<NWebValue>& nwebValue, bool* isOject);

bool ParseBasicTypeNwebValue2NapiValue(napi_env env, const std::shared_ptr<NWebValue>& value, napi_value& napiValue)
{
    napi_status s = napi_ok;
    switch (value->GetType()) {
        case NWebValue::Type::INTEGER:
            s = napi_create_int32(env, value->GetInt(), &napiValue);
            if (s != napi_ok) {
                WVLOG_E("ParseBasicTypeNwebValue2NapiValue napi api call fail");
            }
            break;
        case NWebValue::Type::DOUBLE:
            s = napi_create_double(env, value->GetDouble(), &napiValue);
            if (s != napi_ok) {
                WVLOG_E("ParseBasicTypeNwebValue2NapiValue napi api call fail");
            }
            break;
        case NWebValue::Type::BOOLEAN:
            s = napi_get_boolean(env, value->GetBoolean(), &napiValue);
            if (s != napi_ok) {
                WVLOG_E("ParseBasicTypeNwebValue2NapiValue napi api call fail");
            }
            break;
        case NWebValue::Type::STRING:
            s = napi_create_string_utf8(env, value->GetString().c_str(), NAPI_AUTO_LENGTH, &napiValue);
            if (s != napi_ok) {
                WVLOG_E("ParseBasicTypeNwebValue2NapiValue napi api call fail");
            }
            break;
        default:
            return false;
    }
    return true;
}

napi_value ParseNwebValue2NapiValueHelper(
    napi_env env, std::shared_ptr<NWebValue> value, WebviewJavaScriptResultCallBack::ObjectMap& objectsMap)
{
    napi_value napiValue = nullptr;
    if (!value) {
        napi_get_undefined(env, &napiValue);
        return napiValue;
    }
    if (ParseBasicTypeNwebValue2NapiValue(env, value, napiValue)) {
        return napiValue;
    }
    switch (value->GetType()) {
        case NWebValue::Type::LIST: {
            ParseArrayNwebValue2NapiValue(env, value, napiValue, objectsMap);
            return napiValue;
        }
        case NWebValue::Type::DICTIONARY: {
            ParseDictionaryNwebValue2NapiValue(env, value, napiValue, objectsMap);
            return napiValue;
        }
        case NWebValue::Type::BINARY: {
            auto buff = value->GetBinaryValue();
            JavaScriptOb::ObjectID objId;
            std::string str(buff);
            std::istringstream ss(str);
            ss >> objId;
            auto iter = objectsMap.find(objId);
            if (iter != objectsMap.end()) {
                if (iter->second) {
                    WVLOG_E("ParseNwebValue2NapiValueHelper: type is "
                            "binary, object is found and objectId == %{public}d",
                        objId);
                    napiValue = iter->second->GetValue();
                } else {
                    napi_get_undefined(env, &napiValue);
                }
            }
            return napiValue;
        }
        case NWebValue::Type::NONE:
        default:
            WVLOG_E("ParseNwebValue2NapiValueHelper invalid type");
            break;
    }
    napi_get_undefined(env, &napiValue);
    return napiValue;
}

void ParseArrayNwebValue2NapiValue(napi_env env, const std::shared_ptr<NWebValue>& value, napi_value& napiValue,
    WebviewJavaScriptResultCallBack::ObjectMap& objectsMap)
{
    napi_status s = napi_ok;
    size_t length = value->GetListValueSize();
    s = napi_create_array_with_length(env, length, &napiValue);
    if (s != napi_ok) {
        WVLOG_E("ParseArrayNwebValue2NapiValue napi api call fail");
    }
    for (size_t i = 0; i < length; ++i) {
        auto nPtr = std::make_shared<NWebValue>(value->GetListValue(i));
        s = napi_set_element(env, napiValue, i, ParseNwebValue2NapiValueHelper(env, nPtr, objectsMap));
        if (s != napi_ok) {
            WVLOG_E("ParseArrayNwebValue2NapiValue napi api call fail");
        }
    }
}

void ParseDictionaryNwebValue2NapiValue(napi_env env, const std::shared_ptr<NWebValue>& value, napi_value& napiValue,
    WebviewJavaScriptResultCallBack::ObjectMap& objectsMap)
{
    napi_status s = napi_ok;
    s = napi_create_object(env, &napiValue);
    auto dict = value->GetDictionaryValue();
    for (auto& item : dict) {
        auto nValuePtr = std::make_shared<NWebValue>(item.second);
        auto nKeyPtr = std::make_shared<NWebValue>(item.first);
        s = napi_set_property(env, napiValue, ParseNwebValue2NapiValueHelper(env, nKeyPtr, objectsMap),
            ParseNwebValue2NapiValueHelper(env, nValuePtr, objectsMap));
        if (s != napi_ok) {
            WVLOG_E("ParseDictionaryNwebValue2NapiValue napi api call fail");
        }
    }
}

bool ParseBasicTypeNapiValue2NwebValue(napi_env env, napi_value& value, std::shared_ptr<NWebValue>& nwebValue)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, value, &valueType);
    napi_status s = napi_ok;
    switch (valueType) {
        case napi_undefined: // fallthrough
        case napi_null:
            nwebValue->SetType(NWebValue::Type::NONE);
            break;
        case napi_number: {
            double douVal = 0.0;
            s = napi_get_value_double(env, value, &douVal);
            nwebValue->SetType(NWebValue::Type::DOUBLE);
            nwebValue->SetDouble(douVal);
            break;
        }
        case napi_boolean: {
            bool boolVal;
            s = napi_get_value_bool(env, value, &boolVal);
            nwebValue->SetType(NWebValue::Type::BOOLEAN);
            nwebValue->SetBoolean(boolVal);
            break;
        }
        case napi_symbol: // fallthrough
        case napi_string: {
            std::string strVal;
            if (!NapiParseUtils::ParseString(env, value, strVal)) {
                WVLOG_E("ParseBasicTypeNapiValue2NwebValue NapiParseUtils::ParseString "
                        "failed");
            }
            nwebValue->SetType(NWebValue::Type::STRING);
            nwebValue->SetString(strVal);
            break;
        }
        default:
            return false;
    }
    return true;
}

void ParseNapiValue2NwebValueHelper(napi_env env, napi_value value, std::shared_ptr<NWebValue> nwebValue, bool* isOject)
{
    if (!nwebValue) {
        return;
    }
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, value, &valueType);
    napi_status s = napi_ok;
    if (ParseBasicTypeNapiValue2NwebValue(env, value, nwebValue)) {
        return;
    }
    switch (valueType) {
        case napi_object: {
            bool isArray;
            s = napi_is_array(env, value, &isArray);
            if (s != napi_ok) {
                WVLOG_E("ParseNapiValue2NwebValueHelper napi api call fail");
            }
            if (!isArray) {
                ParseDictionaryNapiValue2NwebValue(env, value, nwebValue, isOject);
                break;
            }
            nwebValue->SetType(NWebValue::Type::LIST);
            size_t size;
            s = napi_get_array_length(env, value, &size);
            if (s != napi_ok) {
                WVLOG_E("ParseNapiValue2NwebValueHelper napi api call fail");
            }
            for (size_t i = 0; i < size; i++) {
                napi_value napiTmp;
                s = napi_get_element(env, value, i, &napiTmp);
                if (s != napi_ok) {
                    WVLOG_E("ParseNapiValue2NwebValueHelper napi api call fail");
                }
                auto nwebTmp = std::make_shared<NWebValue>();
                ParseNapiValue2NwebValueHelper(env, napiTmp, nwebTmp, isOject);
                nwebValue->AddListValue(*nwebTmp);
            }
            break;
        }
        case napi_function: {
            *isOject = true;
            break;
        }
        default: {
            WVLOG_E("ParseNapiValue2NwebValueHelper invalid type");
            break;
        }
    }
}

void ParseDictionaryNapiValue2NwebValue(
    napi_env env, napi_value& value, std::shared_ptr<NWebValue>& nwebValue, bool* isOject)
{
    napi_status s = napi_ok;
    nwebValue->SetType(NWebValue::Type::DICTIONARY);
    napi_value propertyNames;
    s = napi_get_property_names(env, value, &propertyNames);
    if (s != napi_ok) {
        WVLOG_E("ParseDictionaryNapiValue2NwebValue napi api call fail");
    }
    size_t size;
    s = napi_get_array_length(env, propertyNames, &size);
    if (s != napi_ok) {
        WVLOG_E("ParseDictionaryNapiValue2NwebValue napi api call fail");
    }

    for (size_t i = 0; i < size; i++) {
        napi_value napiKeyTmp;
        s = napi_get_element(env, propertyNames, i, &napiKeyTmp);
        if (s != napi_ok) {
            WVLOG_E("ParseDictionaryNapiValue2NwebValue napi api call fail");
        }
        bool hasOwnProperty = false;
        s = napi_has_own_property(env, value, napiKeyTmp, &hasOwnProperty);
        if (s != napi_ok) {
            WVLOG_E("ParseDictionaryNapiValue2NwebValue napi api call fail");
        }
        if (!hasOwnProperty) {
            continue;
        }
        napi_value napiValueTmp;
        s = napi_get_property(env, value, napiKeyTmp, &napiValueTmp);
        if (s != napi_ok) {
            WVLOG_E("ParseDictionaryNapiValue2NwebValue napi api call fail");
        }
        auto nwebValueTmp = std::make_shared<NWebValue>();
        auto nwebKeyTmp = std::make_shared<NWebValue>();
        ParseNapiValue2NwebValueHelper(env, napiKeyTmp, nwebKeyTmp, isOject);
        ParseNapiValue2NwebValueHelper(env, napiValueTmp, nwebValueTmp, isOject);
        nwebValue->AddDictionaryValue(nwebKeyTmp->GetString(), *nwebValueTmp);
    }
}
} // namespace

WebviewJavaScriptResultCallBack::~WebviewJavaScriptResultCallBack()
{
    WVLOG_D("WebviewJavaScriptResultCallBack::~WebviewJavaScriptResultCallBack "
            "called");
    auto iter = objects_.begin();
    while (iter != objects_.end()) {
        std::unique_lock<std::mutex> lk(objectMtx_);
        retainedObjectSet_.erase(iter->second);
        objects_.erase(iter);
        ++iter;
    }
}

void WebviewJavaScriptResultCallBack::UvJsCallbackThreadWoker(uv_work_t* work, int status)
{
    if (work == nullptr) {
        WVLOG_E("uv work is null");
        return;
    }
    WebviewJavaScriptResultCallBack::NapiJsCallBackParm* param =
        reinterpret_cast<WebviewJavaScriptResultCallBack::NapiJsCallBackParm*>(work->data);
    if (param == nullptr) {
        WVLOG_E("NapiJsCallBackParm is null");
        delete work;
        work = nullptr;
        return;
    }
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(param->env, &scope);
    if (scope == nullptr) {
        return;
    }

    std::vector<napi_value> argv = {};
    for (std::shared_ptr<NWebValue> input : param->args) {
        ParseNwebValue2NapiValue(param->env, input, argv, param->objectsMap);
    }

    napi_value callback = param->callback;
    napi_value callResult = nullptr;
    napi_call_function(param->env, nullptr, callback, argv.size(), &argv[0], &callResult);
    // convert to nweb value
    bool isObject = false;
    ParseNapiValue2NwebValue(param->env, callResult, param->value, &isObject);
    if (isObject) {
        param->isObject = true;
        param->object = JavaScriptOb::CreateTransient(param->env, callResult, 0);
    }

    std::unique_lock<std::mutex> lock(param->mutex);
    param->ready = true;
    param->condition.notify_all();
    napi_close_handle_scope(param->env, scope);
}

std::shared_ptr<JavaScriptOb> WebviewJavaScriptResultCallBack::FindObject(JavaScriptOb::ObjectID objectId)
{
    std::unique_lock<std::mutex> lk(objectMtx_);
    auto iter = objects_.find(objectId);
    if (iter != objects_.end()) {
        return iter->second;
    }
    WVLOG_D("WebviewJavaScriptResultCallBack::FindObject Unknown object: objectId = "
            "%{public}d",
        objectId);
    return nullptr;
} // namespace OHOS::NWeb

void WebviewJavaScriptResultCallBack::GetJavaScriptResultInner(napi_env env, int32_t routingId,
    WebviewJavaScriptResultCallBack::NapiJsCallBackParm* param, const std::string& method,
    std::shared_ptr<NWebValue>& ret)
{
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env, &loop);
    uv_work_t* work = new (std::nothrow) uv_work_t;
    if (param == nullptr || work == nullptr || loop == nullptr) {
        return;
    }
    {
        std::unique_lock<std::mutex> lk(objectMtx_);
        for (auto& item : objects_) {
            param->objectsMap.insert(std::make_pair(item.first, item.second));
        }
    }

    work->data = reinterpret_cast<void*>(param);
    uv_queue_work(
        loop, work, [](uv_work_t* work) {}, UvJsCallbackThreadWoker);
    std::unique_lock<std::mutex> lock(param->mutex);
    param->condition.wait(lock, [&param] { return param->ready; });
    if (param->isObject) {
        JavaScriptOb::ObjectID returnedObjectId;
        napi_value object = param->object ? param->object->GetValue() : nullptr;
        if (FindObjectId(param->env, object, &returnedObjectId)) {
            std::unique_lock<std::mutex> lk(objectMtx_);
            objects_[returnedObjectId]->AddHolder(routingId);
            WVLOG_D("WebviewJavaScriptResultCallBack::GetJavaScriptResultInner AddHolder "
                    "called, method = %{public}s",
                method.c_str());
        } else {
            returnedObjectId = AddObject(param->env, object, false, routingId);
            WVLOG_D("WebviewJavaScriptResultCallBack::GetJavaScriptResultInner AddObject "
                    "called, method = %{public}s",
                method.c_str());
        }
        std::string bin = std::to_string(returnedObjectId);
        WVLOG_D("WebviewJavaScriptResultCallBack::GetJavaScriptResultInner returned "
                "CreateTransient objectId = %{public}s",
            bin.c_str());
        ret = std::make_shared<NWebValue>(bin.c_str(), bin.size());
    }
    if (work != nullptr) {
        delete work;
        work = nullptr;
    }
}

std::shared_ptr<NWebValue> WebviewJavaScriptResultCallBack::GetJavaScriptResult(
    std::vector<std::shared_ptr<NWebValue>> args, const std::string& method, const std::string& objName,
    int32_t routingId, int32_t objectId)
{
    // 为了兼容老版本webcotroller方式,classname可能为空
    (void)objName;
    WVLOG_D("WebviewJavaScriptResultCallBack::GetJavaScriptResult method = "
            "%{public}s",
        method.c_str());
    std::shared_ptr<NWebValue> ret = std::make_shared<NWebValue>(NWebValue::Type::NONE);
    std::shared_ptr<JavaScriptOb> jsObj;
    {
        std::unique_lock<std::mutex> lk(objectMtx_);
        if (objects_.find(objectId) == objects_.end() || !(objects_[objectId])) {
            WVLOG_E("WebviewJavaScriptResultCallBack::GetJavaScriptResult object cannot "
                    "be found, method = %{public}s, objectId = %{public}d",
                method.c_str(), objectId);
            return ret;
        }

        jsObj = objects_[objectId];
    }
    if (!jsObj || !(jsObj->HasMethod(method))) {
        WVLOG_E("WebviewJavaScriptResultCallBack::GetJavaScriptResult method cannot "
                "be found, method = %{public}s, objectId = %{public}d",
            method.c_str(), objectId);
        return ret;
    }

    WebviewJavaScriptResultCallBack::NapiJsCallBackParm* param =
        new (std::nothrow) WebviewJavaScriptResultCallBack::NapiJsCallBackParm();
    if (param == nullptr) {
        return ret;
    }
    param->env = jsObj->GetEnv();
    param->callback = jsObj->FindMethod(method);
    param->args = args;
    param->value = ret;

    GetJavaScriptResultInner(jsObj->GetEnv(), routingId, param, method, ret);

    if (param != nullptr) {
        delete param;
        param = nullptr;
    }
    return ret;
}

bool WebviewJavaScriptResultCallBack::FindObjectId(napi_env env, napi_value object, JavaScriptOb::ObjectID* objectId)
{
    *objectId = static_cast<JavaScriptOb::ObjectID>(JavaScriptOb::JavaScriptObjIdErrorCode::WEBCONTROLLERERROR);
    std::unique_lock<std::mutex> lk(objectMtx_);
    for (const auto& pair : objects_) {
        bool result = false;
        napi_status s = napi_strict_equals(env, object, pair.second->GetValue(), &result);
        if (s != napi_ok) {
            WVLOG_E("WebviewJavaScriptResultCallBack::FindObjectId fail");
        }
        if (result) {
            *objectId = pair.first;
            return true;
        }
    }
    return false;
}

bool WebviewJavaScriptResultCallBack::HasJavaScriptObjectMethods(int32_t objectId, const std::string& methodName)
{
    auto obj = FindObject(objectId);
    if (obj) {
        return obj->HasMethod(methodName);
    }
    WVLOG_D("WebviewJavaScriptResultCallBack::HasJavaScriptObjectMethods cannot find "
            "object");
    return false;
}

std::shared_ptr<NWebValue> WebviewJavaScriptResultCallBack::GetJavaScriptObjectMethods(int32_t objectId)
{
    auto obj = FindObject(objectId);
    auto ret = std::make_shared<NWebValue>();
    if (obj) {
        auto methods = obj->GetMethodNames();
        for (auto& method : methods) {
            ret->AddListValue(NWebValue(method));
        }
    }
    return ret;
}

void WebviewJavaScriptResultCallBack::RemoveJavaScriptObjectHolder(int32_t holder, JavaScriptOb::ObjectID objectId)
{
    WVLOG_D("WebviewJavaScriptResultCallBack::RemoveJavaScriptObjectHolder called, "
            "objectId = %{public}d",
        objectId);
    std::unique_lock<std::mutex> lk(objectMtx_);
    auto iter = objects_.find(objectId);
    if (iter == objects_.end()) {
        return;
    }
    auto object = iter->second;
    if (!(object->IsNamed())) {
        object->RemoveHolder(holder);
        if (!(object->HasHolders())) {
            // reminder me: object->ToWeakRef(), object is erased so the destructor
            // called
            retainedObjectSet_.erase(object);
            objects_.erase(iter);
        }
    }
}

void WebviewJavaScriptResultCallBack::RemoveTransientJavaScriptObject()
{
    // remove retainedObjectSet_ and objects_ CreateTransient object
    std::unique_lock<std::mutex> lk(objectMtx_);
    auto iter = objects_.begin();
    while (iter != objects_.end()) {
        if (!(iter->second->IsNamed())) {
            WVLOG_D("WebviewJavaScriptResultCallBack::RemoveTransientJavaScriptObject "
                    "objectId = %{public}d  is removed",
                (int32_t)iter->first);
            // reminder me: object->ToWeakRef(), object is erased so the destructor
            // called
            retainedObjectSet_.erase(iter->second);
            objects_.erase(iter);
        }
        ++iter;
    }

    // remove retainedObjectSet_ named object but not in objects_
    auto iter1 = retainedObjectSet_.begin();
    while (iter1 != retainedObjectSet_.end()) {
        auto iter2 = objects_.begin();
        bool isHasObj = false;
        while (iter2 != objects_.end()) {
            if (*iter1 == iter2->second) {
                isHasObj = true;
                break;
            }
            ++iter2;
        }
        if (!isHasObj) {
            WVLOG_D("WebviewJavaScriptResultCallBack::RemoveTransientJavaScriptObject "
                    "isHasObj == false");
            retainedObjectSet_.erase(*iter1);
        }
        ++iter1;
    }
}

JavaScriptOb::ObjectID WebviewJavaScriptResultCallBack::AddObject(
    napi_env env, const napi_value& object, bool methodName, int32_t holder)
{
    auto new_object =
        methodName ? JavaScriptOb::CreateNamed(env, object) : JavaScriptOb::CreateTransient(env, object, holder);
    JavaScriptOb::ObjectID objectId;
    {
        std::unique_lock<std::mutex> lk(objectMtx_);
        objectId = nextObjectId_++;
        WVLOG_D("WebviewJavaScriptResultCallBack::AddObject objectId = "
                "%{public}d",
            static_cast<int32_t>(objectId));
        objects_[objectId] = new_object;
        retainedObjectSet_.insert(new_object);
    }
    return objectId;
}

JavaScriptOb::ObjectID WebviewJavaScriptResultCallBack::AddNamedObject(
    napi_env env, napi_value& obj, const std::string& objName)
{
    JavaScriptOb::ObjectID objectId;
    NamedObjectMap::iterator iter = namedObjects_.find(objName);
    bool methodName = FindObjectId(env, obj, &objectId);
    if (methodName && iter != namedObjects_.end() && iter->second == objectId) {
        // Nothing to do.
        return objectId;
    }
    if (iter != namedObjects_.end()) {
        RemoveNamedObject(iter->first);
    }
    if (methodName) {
        std::unique_lock<std::mutex> lk(objectMtx_);
        objects_[objectId]->AddName();
    } else {
        objectId = AddObject(env, obj, true, 0);
    }
    namedObjects_[objName] = objectId;
    return objectId;
}

std::unordered_map<std::string, std::shared_ptr<JavaScriptOb>> WebviewJavaScriptResultCallBack::GetObjects()
{
    // Get named objects
    std::unordered_map<std::string, std::shared_ptr<JavaScriptOb>> ret;
    for (auto iter = namedObjects_.begin(); iter != namedObjects_.end(); iter++) {
        if (objects_.find(iter->second) != objects_.end()) {
            ret.emplace(iter->first, objects_[iter->second]);
        }
    }
    return ret;
}

JavaScriptOb::ObjectID WebviewJavaScriptResultCallBack::RegisterJavaScriptProxy(
    napi_env env, napi_value obj, const std::string& objName, const std::vector<std::string>& methodList)
{
    JavaScriptOb::ObjectID objId = AddNamedObject(env, obj, objName);
    std::unique_lock<std::mutex> lk(objectMtx_);
    // set up named object method
    if (namedObjects_.find(objName) != namedObjects_.end() && objects_[namedObjects_[objName]]) {
        objects_[namedObjects_[objName]]->SetMethods(methodList);
    }
    WVLOG_D("WebviewJavaScriptResultCallBack::RegisterJavaScriptProxy called, "
            "objectId = %{public}d",
        static_cast<int32_t>(objId));
    return objId;
}

bool WebviewJavaScriptResultCallBack::RemoveNamedObject(const std::string& name)
{
    WVLOG_D("WebviewJavaScriptResultCallBack::RemoveNamedObject called, "
            "name = %{public}s",
        name.c_str());
    NamedObjectMap::iterator iter = namedObjects_.find(name);
    if (iter == namedObjects_.end()) {
        return false;
    }
    const std::string methodName(name);
    std::unique_lock<std::mutex> lk(objectMtx_);
    if (objects_[iter->second]) {
        objects_[iter->second]->RemoveName();
    }
    namedObjects_.erase(iter);
    return true;
}

bool WebviewJavaScriptResultCallBack::DeleteJavaScriptRegister(const std::string& objName)
{
    return RemoveNamedObject(objName);
}

void WebviewJavaScriptResultCallBack::ParseNwebValue2NapiValue(
    napi_env env, std::shared_ptr<NWebValue> value, std::vector<napi_value>& argv, ObjectMap& objectsMap)
{
    argv.push_back(ParseNwebValue2NapiValueHelper(env, value, objectsMap));
}

void WebviewJavaScriptResultCallBack::ParseNapiValue2NwebValue(
    napi_env env, napi_value value, std::shared_ptr<NWebValue> nwebValue, bool* isObject)
{
    ParseNapiValue2NwebValueHelper(env, value, nwebValue, isObject);
}
}
