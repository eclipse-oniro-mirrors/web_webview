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

#include "core/common/container_scope.h"
#include "napi_parse_utils.h"
#include "native_engine/native_engine.h"
#include "nweb_log.h"

namespace OHOS::NWeb {
namespace {
napi_handle_scope OpenScope(napi_env env)
{
    napi_handle_scope scope = nullptr;
    NAPI_CALL(env, napi_open_handle_scope(env, &scope));
    return scope;
}

void CloseScope(napi_env env, napi_handle_scope scope)
{
    (void)napi_close_handle_scope(env, scope);
}

void CreateUvQueueWorkEnhanced(napi_env env, WebviewJavaScriptResultCallBack::NapiJsCallBackParm* data,
    void (*handler)(napi_env env, napi_status status, WebviewJavaScriptResultCallBack::NapiJsCallBackParm* data))
{
    uv_loop_s* loop = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_uv_event_loop(env, &loop));
    class WorkData {
    public:
        WorkData() = delete;

        WorkData(napi_env env, WebviewJavaScriptResultCallBack::NapiJsCallBackParm* data,
            void (*handler)(
                napi_env env, napi_status status, WebviewJavaScriptResultCallBack::NapiJsCallBackParm* data))
            : env_(env), data_(data), handler_(handler)
        {}

        napi_env env_;
        WebviewJavaScriptResultCallBack::NapiJsCallBackParm* data_;
        void (*handler_)(napi_env env, napi_status status, WebviewJavaScriptResultCallBack::NapiJsCallBackParm* data);
    };

    auto workData = new WorkData(env, data, handler);
    auto work = new uv_work_t;
    work->data = reinterpret_cast<void*>(workData);

    auto callback = [](uv_work_t* work, int status) {
        auto workData = static_cast<WorkData*>(work->data);
        if (!workData) {
            delete work;
            return;
        }

        if (!workData->env_ || !workData->data_ || !workData->handler_) {
            delete workData;
            delete work;
            return;
        }

        napi_env env = workData->env_;
        auto closeScope = [env](napi_handle_scope scope) { CloseScope(env, scope); };
        std::unique_ptr<napi_handle_scope__, decltype(closeScope)> scope(OpenScope(env), closeScope);

        workData->handler_(workData->env_, static_cast<napi_status>(status), workData->data_);

        delete workData;
        delete work;
    };
    (void)uv_queue_work_with_qos(
        loop, work, [](uv_work_t* work) {}, callback, uv_qos_user_initiated);
}

bool CreateNapiJsCallBackParm(WebviewJavaScriptResultCallBack::NapiJsCallBackInParm*& inParam,
    WebviewJavaScriptResultCallBack::NapiJsCallBackOutParm*& outParam,
    WebviewJavaScriptResultCallBack::NapiJsCallBackParm*& param)
{
    inParam = new (std::nothrow) WebviewJavaScriptResultCallBack::NapiJsCallBackInParm();
    if (inParam == nullptr) {
        return false;
    }
    outParam = new (std::nothrow) WebviewJavaScriptResultCallBack::NapiJsCallBackOutParm();
    if (outParam == nullptr) {
        delete inParam;
        return false;
    }
    param = new (std::nothrow) WebviewJavaScriptResultCallBack::NapiJsCallBackParm();
    if (param == nullptr) {
        delete inParam;
        delete outParam;
        return false;
    }
    return true;
}

void DeleteNapiJsCallBackParm(WebviewJavaScriptResultCallBack::NapiJsCallBackInParm* inParam,
    WebviewJavaScriptResultCallBack::NapiJsCallBackOutParm* outParam,
    WebviewJavaScriptResultCallBack::NapiJsCallBackParm* param)
{
    if (inParam != nullptr) {
        delete inParam;
        inParam = nullptr;
    }
    if (outParam != nullptr) {
        delete outParam;
        outParam = nullptr;
    }

    if (param != nullptr) {
        delete param;
        param = nullptr;
    }
}

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

void ParseNwebValue2NapiValue(napi_env env, std::shared_ptr<NWebValue> value, std::vector<napi_value>& argv,
    WebviewJavaScriptResultCallBack::ObjectMap objectsMap)
{
    argv.push_back(ParseNwebValue2NapiValueHelper(env, value, objectsMap));
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
            uint32_t size;
            s = napi_get_array_length(env, value, &size);
            if (s != napi_ok) {
                WVLOG_E("ParseNapiValue2NwebValueHelper napi api call fail");
            }
            for (uint32_t i = 0; i < size; i++) {
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
    uint32_t size;
    s = napi_get_array_length(env, propertyNames, &size);
    if (s != napi_ok) {
        WVLOG_E("ParseDictionaryNapiValue2NwebValue napi api call fail");
    }

    for (uint32_t i = 0; i < size; i++) {
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

void ParseNapiValue2NwebValue(napi_env env, napi_value value, std::shared_ptr<NWebValue> nwebValue, bool* isObject)
{
    ParseNapiValue2NwebValueHelper(env, value, nwebValue, isObject);
}
} // namespace

WebviewJavaScriptResultCallBack::~WebviewJavaScriptResultCallBack() {}

std::shared_ptr<JavaScriptOb> WebviewJavaScriptResultCallBack::FindObject(JavaScriptOb::ObjectID objectId)
{
    auto iter = objects_.find(objectId);
    if (iter != objects_.end()) {
        return iter->second;
    }
    WVLOG_E("WebviewJavaScriptResultCallBack::FindObject Unknown object: objectId = "
            "%{public}d",
        objectId);
    return nullptr;
}

void ExecuteGetJavaScriptResult(
    napi_env env, napi_status status, WebviewJavaScriptResultCallBack::NapiJsCallBackParm* param)
{
    auto* inParam = static_cast<WebviewJavaScriptResultCallBack::NapiJsCallBackInParm*>(param->input);
    auto* outParam = static_cast<WebviewJavaScriptResultCallBack::NapiJsCallBackOutParm*>(param->out);
    std::shared_ptr<JavaScriptOb> jsObj = inParam->webJsResCb->FindObject(inParam->objId);
    if (!jsObj) {
        std::unique_lock<std::mutex> lock(param->mutex);
        param->ready = true;
        param->condition.notify_all();
        return;
    }
    Ace::ContainerScope containerScope(jsObj->GetContainerScopeId());
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env, &scope);
    if (!scope) {
        std::unique_lock<std::mutex> lock(param->mutex);
        param->ready = true;
        param->condition.notify_all();
        return;
    }
    if (jsObj && (jsObj->HasMethod(inParam->methodName))) {
        std::vector<napi_value> argv = {};
        auto nwebArgs = *(static_cast<std::vector<std::shared_ptr<NWebValue>>*>(inParam->data));
        for (std::shared_ptr<NWebValue> input : nwebArgs) {
            ParseNwebValue2NapiValue(env, input, argv, inParam->webJsResCb->GetObjectMap());
        }
        napi_value callback = jsObj->FindMethod(inParam->methodName);
        napi_value callResult = nullptr;
        napi_call_function(env, jsObj->GetValue(), callback, argv.size(), &argv[0], &callResult);
        bool isObject = false;
        ParseNapiValue2NwebValue(
            env, callResult, *(static_cast<std::shared_ptr<NWebValue>*>(outParam->ret)), &isObject);
        if (isObject) {
            JavaScriptOb::ObjectID returnedObjectId;
            if (inParam->webJsResCb->FindObjectIdInJsTd(env, callResult, &returnedObjectId)) {
                inParam->webJsResCb->FindObject(returnedObjectId)->AddHolder(inParam->frameRoutingId);
            } else {
                returnedObjectId = inParam->webJsResCb->AddObject(env, callResult, false, inParam->frameRoutingId);
            }
            std::string bin = std::to_string(returnedObjectId);
            *(static_cast<std::shared_ptr<NWebValue>*>(outParam->ret)) =
                std::make_shared<NWebValue>(bin.c_str(), bin.size());
        }
    }
    napi_close_handle_scope(env, scope);
    std::unique_lock<std::mutex> lock(param->mutex);
    param->ready = true;
    param->condition.notify_all();
}

std::shared_ptr<NWebValue> WebviewJavaScriptResultCallBack::GetJavaScriptResult(
    std::vector<std::shared_ptr<NWebValue>> args, const std::string& method, const std::string& objName,
    int32_t routingId, int32_t objectId)
{
    (void)objName; // to be compatible with older webcotroller, classname may be empty
    WVLOG_D("GetJavaScriptResult method = %{public}s", method.c_str());
    std::shared_ptr<NWebValue> ret = std::make_shared<NWebValue>(NWebValue::Type::NONE);
    std::shared_ptr<JavaScriptOb> jsObj = FindObject(objectId);
    if (!jsObj || !jsObj->HasMethod(method)) {
        return ret;
    }
    auto engine = reinterpret_cast<NativeEngine*>(jsObj->GetEnv());
    if (engine == nullptr) {
        return ret;
    }
    if (pthread_self() == engine->GetTid()) {
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(jsObj->GetEnv(), &scope);
        if (scope == nullptr) {
            return ret;
        }
        WVLOG_D("get javaScript result already in js thread");
        std::vector<napi_value> argv = {};
        for (std::shared_ptr<NWebValue> input : args) {
            ParseNwebValue2NapiValue(jsObj->GetEnv(), input, argv, GetObjectMap());
        }
        napi_value callback = jsObj->FindMethod(method);
        napi_value callResult = nullptr;
        napi_call_function(jsObj->GetEnv(), jsObj->GetValue(), callback, argv.size(), &argv[0], &callResult);
        bool isObject = false;
        ParseNapiValue2NwebValue(jsObj->GetEnv(), callResult, ret, &isObject);
        if (isObject) {
            JavaScriptOb::ObjectID returnedObjectId;
            if (FindObjectIdInJsTd(jsObj->GetEnv(), callResult, &returnedObjectId)) {
                FindObject(returnedObjectId)->AddHolder(routingId);
            } else {
                returnedObjectId = AddObject(jsObj->GetEnv(), callResult, false, routingId);
            }
            std::string bin = std::to_string(returnedObjectId);
            ret = std::make_shared<NWebValue>(bin.c_str(), bin.size());
        }
        napi_close_handle_scope(jsObj->GetEnv(), scope);
        return ret;
    } else {
        WVLOG_D("get javaScript result, not in js thread, post task to js thread");
        return PostGetJavaScriptResultToJsThread(args, method, objName, routingId, objectId);
    }
}

std::shared_ptr<NWebValue> WebviewJavaScriptResultCallBack::PostGetJavaScriptResultToJsThread(
    std::vector<std::shared_ptr<NWebValue>> args, const std::string& method, const std::string& objName,
    int32_t routingId, int32_t objectId)
{
    // to be compatible with older webcotroller, classname may be empty
    (void)objName;
    WVLOG_D("WebviewJavaScriptResultCallBack::GetJavaScriptResult method = "
            "%{public}s",
        method.c_str());
    std::shared_ptr<NWebValue> ret = std::make_shared<NWebValue>(NWebValue::Type::NONE);
    std::shared_ptr<JavaScriptOb> jsObj = FindObject(objectId);
    if (!jsObj) {
        return ret;
    }
    napi_env env = jsObj->GetEnv();
    WebviewJavaScriptResultCallBack::NapiJsCallBackInParm* inParam = nullptr;
    WebviewJavaScriptResultCallBack::NapiJsCallBackOutParm* outParam = nullptr;
    WebviewJavaScriptResultCallBack::NapiJsCallBackParm* param = nullptr;
    if (!CreateNapiJsCallBackParm(inParam, outParam, param)) {
        return ret;
    }
    inParam->webJsResCb = this;
    inParam->frameRoutingId = routingId;
    inParam->objId = objectId;
    inParam->methodName = method;
    inParam->data = reinterpret_cast<void*>(&args);
    outParam->ret = reinterpret_cast<void*>(&ret);
    param->input = reinterpret_cast<void*>(inParam);
    param->out = reinterpret_cast<void*>(outParam);
    param->env = env;

    CreateUvQueueWorkEnhanced(env, param, ExecuteGetJavaScriptResult);
    {
        std::unique_lock<std::mutex> lock(param->mutex);
        param->condition.wait(lock, [&param] { return param->ready; });
    }
    DeleteNapiJsCallBackParm(inParam, outParam, param);
    return ret;
}

bool WebviewJavaScriptResultCallBack::FindObjectIdInJsTd(
    napi_env env, napi_value object, JavaScriptOb::ObjectID* objectId)
{
    *objectId = static_cast<JavaScriptOb::ObjectID>(JavaScriptOb::JavaScriptObjIdErrorCode::WEBVIEWCONTROLLERERROR);
    for (const auto& pair : objects_) {
        bool result = false;
        napi_status s = napi_strict_equals(env, object, pair.second->GetValue(), &result);
        if (s != napi_ok) {
            WVLOG_E("WebviewJavaScriptResultCallBack::FindObjectIdInJsTd fail");
        }
        if (result) {
            *objectId = pair.first;
            return true;
        }
    }
    return false;
}

void ExecuteHasJavaScriptObjectMethods(
    napi_env env, napi_status status, WebviewJavaScriptResultCallBack::NapiJsCallBackParm* param)
{
    if (!param) {
        std::unique_lock<std::mutex> lock(param->mutex);
        param->ready = true;
        param->condition.notify_all();
        return;
    }

    auto* inParam = static_cast<WebviewJavaScriptResultCallBack::NapiJsCallBackInParm*>(param->input);
    auto* outParam = static_cast<WebviewJavaScriptResultCallBack::NapiJsCallBackOutParm*>(param->out);

    std::shared_ptr<JavaScriptOb> jsObj = inParam->webJsResCb->FindObject(inParam->objId);
    if (!jsObj) {
        std::unique_lock<std::mutex> lock(param->mutex);
        param->ready = true;
        param->condition.notify_all();
        return;
    }
    Ace::ContainerScope containerScope(jsObj->GetContainerScopeId());

    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env, &scope);
    if (scope) {
        if (jsObj && jsObj->HasMethod(inParam->methodName)) {
            *(static_cast<bool*>(outParam->ret)) = true;
        } else {
            WVLOG_D("WebviewJavaScriptResultCallBack::HasJavaScriptObjectMethods cannot find "
                    "object");
        }
        napi_close_handle_scope(env, scope);
    }

    std::unique_lock<std::mutex> lock(param->mutex);
    param->ready = true;
    param->condition.notify_all();
}

bool WebviewJavaScriptResultCallBack::PostHasJavaScriptObjectMethodsToJsThread(
    int32_t objectId, const std::string& methodName)
{
    bool ret = false;
    std::shared_ptr<JavaScriptOb> jsObj = FindObject(objectId);
    if (!jsObj) {
        return false;
    }
    napi_env env = jsObj->GetEnv();
    WebviewJavaScriptResultCallBack::NapiJsCallBackInParm* inParam = nullptr;
    WebviewJavaScriptResultCallBack::NapiJsCallBackOutParm* outParam = nullptr;
    WebviewJavaScriptResultCallBack::NapiJsCallBackParm* param = nullptr;
    if (!CreateNapiJsCallBackParm(inParam, outParam, param)) {
        return false;
    }

    inParam->webJsResCb = this;
    inParam->objId = objectId;
    inParam->methodName = methodName;
    outParam->ret = reinterpret_cast<void*>(&ret);
    param->input = reinterpret_cast<void*>(inParam);
    param->out = reinterpret_cast<void*>(outParam);
    param->env = env;

    CreateUvQueueWorkEnhanced(env, param, ExecuteHasJavaScriptObjectMethods);

    {
        std::unique_lock<std::mutex> lock(param->mutex);
        param->condition.wait(lock, [&param] { return param->ready; });
    }
    DeleteNapiJsCallBackParm(inParam, outParam, param);
    return ret;
}

bool WebviewJavaScriptResultCallBack::HasJavaScriptObjectMethods(int32_t objectId, const std::string& methodName)
{
    bool ret = false;
    std::shared_ptr<JavaScriptOb> jsObj = FindObject(objectId);
    if (!jsObj) {
        return false;
    }
    napi_env env = jsObj->GetEnv();
    auto engine = reinterpret_cast<NativeEngine*>(env);
    if (engine == nullptr) {
        return ret;
    }
    if (pthread_self() == engine->GetTid()) {
        WVLOG_D("has javaScript object methods already in js thread");
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            return ret;
        }

        if (jsObj && jsObj->HasMethod(methodName)) {
            ret = true;
        } else {
            WVLOG_D("WebviewJavaScriptResultCallBack::HasJavaScriptObjectMethods cannot find "
                    "object");
        }

        napi_close_handle_scope(env, scope);
        return ret;
    } else {
        WVLOG_D("has javaScript object methods, not in js thread, post task to js thread");
        return PostHasJavaScriptObjectMethodsToJsThread(objectId, methodName);
    }
}

void ExecuteGetJavaScriptObjectMethods(
    napi_env env, napi_status status, WebviewJavaScriptResultCallBack::NapiJsCallBackParm* param)
{
    if (!param) {
        std::unique_lock<std::mutex> lock(param->mutex);
        param->ready = true;
        param->condition.notify_all();
        return;
    }

    auto* inParam = static_cast<WebviewJavaScriptResultCallBack::NapiJsCallBackInParm*>(param->input);
    auto* outParam = static_cast<WebviewJavaScriptResultCallBack::NapiJsCallBackOutParm*>(param->out);

    std::shared_ptr<JavaScriptOb> jsObj = inParam->webJsResCb->FindObject(inParam->objId);
    if (!jsObj) {
        std::unique_lock<std::mutex> lock(param->mutex);
        param->ready = true;
        param->condition.notify_all();
        return;
    }
    Ace::ContainerScope containerScope(jsObj->GetContainerScopeId());

    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env, &scope);

    if (scope) {
        if (jsObj) {
            auto methods = jsObj->GetMethodNames();
            for (auto& method : methods) {
                (*(static_cast<std::shared_ptr<NWebValue>*>(outParam->ret)))->AddListValue(NWebValue(method));
            }
        }
        napi_close_handle_scope(env, scope);
    }

    std::unique_lock<std::mutex> lock(param->mutex);
    param->ready = true;
    param->condition.notify_all();
}

std::shared_ptr<NWebValue> WebviewJavaScriptResultCallBack::PostGetJavaScriptObjectMethodsToJsThread(int32_t objectId)
{
    auto ret = std::make_shared<NWebValue>(NWebValue::Type::LIST);
    std::shared_ptr<JavaScriptOb> jsObj = FindObject(objectId);
    if (!jsObj) {
        return ret;
    }
    napi_env env = jsObj->GetEnv();
    WebviewJavaScriptResultCallBack::NapiJsCallBackInParm* inParam = nullptr;
    WebviewJavaScriptResultCallBack::NapiJsCallBackOutParm* outParam = nullptr;
    WebviewJavaScriptResultCallBack::NapiJsCallBackParm* param = nullptr;
    if (!CreateNapiJsCallBackParm(inParam, outParam, param)) {
        return ret;
    }

    inParam->webJsResCb = this;
    inParam->objId = objectId;
    outParam->ret = reinterpret_cast<void*>(&ret);
    param->input = reinterpret_cast<void*>(inParam);
    param->out = reinterpret_cast<void*>(outParam);
    param->env = env;

    CreateUvQueueWorkEnhanced(env, param, ExecuteGetJavaScriptObjectMethods);

    {
        std::unique_lock<std::mutex> lock(param->mutex);
        param->condition.wait(lock, [&param] { return param->ready; });
    }
    DeleteNapiJsCallBackParm(inParam, outParam, param);
    return ret;
}

std::shared_ptr<NWebValue> WebviewJavaScriptResultCallBack::GetJavaScriptObjectMethods(int32_t objectId)
{
    auto ret = std::make_shared<NWebValue>(NWebValue::Type::LIST);
    std::shared_ptr<JavaScriptOb> jsObj = FindObject(objectId);
    if (!jsObj) {
        return ret;
    }
    napi_env env = jsObj->GetEnv();
    auto engine = reinterpret_cast<NativeEngine*>(env);
    if (engine == nullptr) {
        return ret;
    }

    if (pthread_self() == engine->GetTid()) {
        WVLOG_D("get javaScript object methods already in js thread");
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            return ret;
        }

        if (jsObj) {
            auto methods = jsObj->GetMethodNames();
            for (auto& method : methods) {
                ret->AddListValue(NWebValue(method));
            }
        }

        napi_close_handle_scope(env, scope);
        return ret;
    } else {
        WVLOG_D("get javaScript object methods, not in js thread, post task to js thread");
        return PostGetJavaScriptObjectMethodsToJsThread(objectId);
    }
}

void WebviewJavaScriptResultCallBack::RemoveJavaScriptObjectHolderInJsTd(
    int32_t holder, JavaScriptOb::ObjectID objectId)
{
    std::shared_ptr<JavaScriptOb> jsObj = FindObject(objectId);
    if (jsObj && !(jsObj->IsNamed())) {
        jsObj->RemoveHolder(holder);
        if (!(jsObj->HasHolders())) {
            // reminder me: object->ToWeakRef(), object is erased so the destructor
            // called
            retainedObjectSet_.erase(jsObj);
            objects_.erase(objects_.find(objectId));
        }
    }
}

void ExecuteRemoveJavaScriptObjectHolder(
    napi_env env, napi_status status, WebviewJavaScriptResultCallBack::NapiJsCallBackParm* param)
{
    if (!param) {
        std::unique_lock<std::mutex> lock(param->mutex);
        param->ready = true;
        param->condition.notify_all();
        return;
    }

    auto* inParam = static_cast<WebviewJavaScriptResultCallBack::NapiJsCallBackInParm*>(param->input);

    std::shared_ptr<JavaScriptOb> jsObj = inParam->webJsResCb->FindObject(inParam->objId);
    if (!jsObj) {
        std::unique_lock<std::mutex> lock(param->mutex);
        param->ready = true;
        param->condition.notify_all();
        return;
    }
    Ace::ContainerScope containerScope(jsObj->GetContainerScopeId());

    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env, &scope);

    if (scope) {
        inParam->webJsResCb->RemoveJavaScriptObjectHolderInJsTd(inParam->frameRoutingId, inParam->objId);
        napi_close_handle_scope(env, scope);
    }

    std::unique_lock<std::mutex> lock(param->mutex);
    param->ready = true;
    param->condition.notify_all();
}

void WebviewJavaScriptResultCallBack::PostRemoveJavaScriptObjectHolderToJsThread(
    int32_t holder, JavaScriptOb::ObjectID objectId)
{
    WVLOG_D("WebviewJavaScriptResultCallBack::RemoveJavaScriptObjectHolder called, "
            "objectId = %{public}d",
        objectId);
    std::shared_ptr<JavaScriptOb> jsObj = FindObject(objectId);
    if (!jsObj) {
        return;
    }
    napi_env env = jsObj->GetEnv();
    WebviewJavaScriptResultCallBack::NapiJsCallBackInParm* inParam = nullptr;
    WebviewJavaScriptResultCallBack::NapiJsCallBackOutParm* outParam = nullptr;
    WebviewJavaScriptResultCallBack::NapiJsCallBackParm* param = nullptr;
    if (!CreateNapiJsCallBackParm(inParam, outParam, param)) {
        return;
    }

    inParam->webJsResCb = this;
    inParam->objId = objectId;
    inParam->frameRoutingId = holder;
    param->input = reinterpret_cast<void*>(inParam);
    param->out = reinterpret_cast<void*>(outParam);
    param->env = env;

    CreateUvQueueWorkEnhanced(env, param, ExecuteRemoveJavaScriptObjectHolder);

    {
        std::unique_lock<std::mutex> lock(param->mutex);
        param->condition.wait(lock, [&param] { return param->ready; });
    }
    DeleteNapiJsCallBackParm(inParam, outParam, param);
}

void WebviewJavaScriptResultCallBack::RemoveJavaScriptObjectHolder(int32_t holder, JavaScriptOb::ObjectID objectId)
{
    WVLOG_D("WebviewJavaScriptResultCallBack::RemoveJavaScriptObjectHolder called, "
            "objectId = %{public}d",
        objectId);
    std::shared_ptr<JavaScriptOb> jsObj = FindObject(objectId);
    if (!jsObj) {
        return;
    }
    napi_env env = jsObj->GetEnv();
    auto engine = reinterpret_cast<NativeEngine*>(env);
    if (engine == nullptr) {
        return;
    }
    if (pthread_self() == engine->GetTid()) {
        WVLOG_D("remove javaScript object holder already in js thread");
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            return;
        }

        RemoveJavaScriptObjectHolderInJsTd(holder, objectId);

        napi_close_handle_scope(env, scope);
        return;
    } else {
        WVLOG_D("remove javaScript object holder, not in js thread, post task to js thread");
        PostRemoveJavaScriptObjectHolderToJsThread(holder, objectId);
    }
}

void WebviewJavaScriptResultCallBack::RemoveTransientJavaScriptObject()
{
    // remove retainedObjectSet_ and objects_ CreateTransient object
    auto iter = objects_.begin();
    while (iter != objects_.end()) {
        if (!(iter->second->IsNamed())) {
            WVLOG_D("WebviewJavaScriptResultCallBack::RemoveTransientJavaScriptObject "
                    "objectId = %{public}d  is removed",
                (int32_t)iter->first);
            // reminder me: object->ToWeakRef(), object is erased so the destructor called
            retainedObjectSet_.erase(iter->second);
            objects_.erase(iter++);
        } else {
            ++iter;
        }
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
    JavaScriptOb::ObjectID objectId;
    {
        int32_t containerScopeId = Ace::ContainerScope::CurrentId();
        auto new_object = methodName ? JavaScriptOb::CreateNamed(env, containerScopeId, object)
                                     : JavaScriptOb::CreateTransient(env, containerScopeId, object, holder);
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
    bool methodName = FindObjectIdInJsTd(env, obj, &objectId);
    if (methodName && iter != namedObjects_.end() && iter->second == objectId) {
        // Nothing to do.
        return objectId;
    }
    if (iter != namedObjects_.end()) {
        RemoveNamedObject(iter->first);
    }
    if (methodName) {
        objects_[objectId]->AddName();
    } else {
        objectId = AddObject(env, obj, true, 0);
    }
    namedObjects_[objName] = objectId;
    return objectId;
}

std::unordered_map<std::string, std::shared_ptr<JavaScriptOb>> WebviewJavaScriptResultCallBack::GetNamedObjects()
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

WebviewJavaScriptResultCallBack::ObjectMap WebviewJavaScriptResultCallBack::GetObjectMap()
{
    return objects_;
}

JavaScriptOb::ObjectID WebviewJavaScriptResultCallBack::RegisterJavaScriptProxy(
    napi_env env, napi_value obj, const std::string& objName, const std::vector<std::string>& methodList)
{
    JavaScriptOb::ObjectID objId = AddNamedObject(env, obj, objName);
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
} // namespace OHOS::NWeb
