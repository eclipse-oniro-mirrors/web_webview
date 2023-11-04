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

#ifndef NWEB_WEBVIEW_JAVASCRIPT_RESULT_CALLBACK_IMPL_H
#define NWEB_WEBVIEW_JAVASCRIPT_RESULT_CALLBACK_IMPL_H

#include <condition_variable>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi_parse_utils.h"
#include "nweb_javascript_result_callback.h"
#include "nweb_log.h"
#include "nweb_value.h"
#include "uv.h"

namespace OHOS::NWeb {

class JavaScriptOb {
public:
    // 为了兼容老版本webcontroller, 要保持跟ace和core侧定义一致
    enum class JavaScriptObjIdErrorCode : int32_t { WEBCONTROLLERERROR = -2, WEBVIEWCONTROLLERERROR = -1, END = 0 };

    typedef int32_t ObjectID;

    static std::shared_ptr<JavaScriptOb> CreateNamed(napi_env env, napi_value value, size_t refCount = 1)
    {
        return std::make_shared<JavaScriptOb>(env, value, refCount);
    }
    static std::shared_ptr<JavaScriptOb> CreateTransient(
        napi_env env, napi_value value, int32_t holder, size_t refCount = 1)
    {
        std::set<int32_t> holders;
        holders.insert(holder);
        return std::make_shared<JavaScriptOb>(env, value, holders, refCount);
    }

    JavaScriptOb(napi_env env, napi_value value, size_t refCount = 1)
        : env_(env), isStrongRef_(refCount != 0), namesCount_(1)
    {
        napi_status s = napi_create_reference(env, value, refCount, &obj_ref_);
        if (s != napi_ok) {
            WVLOG_E("create javascript obj fail");
        }
    }
    JavaScriptOb(napi_env env, napi_value value, std::set<int32_t> holders, size_t refCount = 1)
        : env_(env), isStrongRef_(refCount != 0), namesCount_(0), holders_(holders)
    {
        napi_status s = napi_create_reference(env, value, refCount, &obj_ref_);
        if (s != napi_ok) {
            WVLOG_E("create javascript obj fail");
        }
    }

    JavaScriptOb(const JavaScriptOb& job)
    {
        *this = job;
    }

    JavaScriptOb(JavaScriptOb&& job)
    {
        *this = std::move(job);
    }

    JavaScriptOb& operator=(const JavaScriptOb& job)
    {
        if (this != &job) {
            Delete();
            env_ = job.env_;
            isStrongRef_ = job.isStrongRef_;
            if (isStrongRef_) {
                obj_ref_ = job.obj_ref_;
                napi_status s = napi_reference_ref(env_, obj_ref_, nullptr);
                if (s != napi_ok) {
                    WVLOG_E("JavaScriptOb copy assign fail");
                }
            } else {
                napi_status s = CreateNewWeakRef(env_, job.obj_ref_, &obj_ref_);
                if (s != napi_ok) {
                    WVLOG_E("JavaScriptOb copy assign fail");
                }
            }
        }
        return *this;
    }

    JavaScriptOb& operator=(JavaScriptOb&& job)
    {
        if (this != &job) {
            Delete();
            env_ = job.env_;
            obj_ref_ = job.obj_ref_;
            isStrongRef_ = job.isStrongRef_;
            job.obj_ref_ = nullptr;
        }
        return *this;
    }

    ~JavaScriptOb()
    {
        Delete();
    }

    napi_env GetEnv() const
    {
        return env_;
    }

    bool IsEmpty() const
    {
        return !obj_ref_;
    }

    bool IsStrongRef()
    {
        return isStrongRef_;
    }

    napi_value GetValue() const
    {
        napi_value result = nullptr;
        napi_get_reference_value(env_, obj_ref_, &result);
        return result;
    }

    void ToWeakRef()
    {
        if (!isStrongRef_ || !obj_ref_) {
            return;
        }

        if (Release() == 0) {
            isStrongRef_ = false;
            return;
        }

        isStrongRef_ = false;
        napi_status s = CreateNewWeakRef(env_, obj_ref_, &obj_ref_);
        if (s != napi_ok) {
            WVLOG_E("JavaScriptOb ToWeakRef fail");
        }
    }

    bool IsNamed()
    {
        return namesCount_ > 0;
    }
    void AddName()
    {
        ++namesCount_;
    }
    void RemoveName()
    {
        --namesCount_;
    }

    // The following methods are called on the background thread.
    bool HasHolders()
    {
        return !holders_.empty();
    }
    void AddHolder(int32_t holder)
    {
        holders_.insert(holder);
    }
    void RemoveHolder(int32_t holder)
    {
        holders_.erase(holder);
    }

    std::vector<std::string> GetMethodNames()
    {
        if (!isMethodsSetup_) {
            SetUpMethods();
        }
        return methods_;
    }

    bool HasMethod(const std::string& methodName)
    {
        if (!isMethodsSetup_) {
            SetUpMethods();
        }
        for (std::vector<std::string>::iterator iter = methods_.begin(); iter != methods_.end(); ++iter) {
            if (*iter == methodName) {
                return true;
            }
        }
        return false;
    }

    napi_value FindMethod(const std::string& methodName)
    {
        if (!isMethodsSetup_) {
            SetUpMethods();
        }

        if (HasMethod(methodName)) {
            bool hasFunc = false;
            napi_value result = nullptr;
            napi_valuetype valueType = napi_undefined;
            napi_value obj = GetValue();

            napi_status s = napi_has_named_property(env_, obj, methodName.c_str(), &hasFunc);
            if (s != napi_ok) {
                WVLOG_E("JavaScriptOb FindMethod fail");
                return nullptr;
            }
            if (!hasFunc) {
                WVLOG_E("JavaScriptOb FindMethod fail");
                return nullptr;
            }
            s = napi_get_named_property(env_, obj, methodName.c_str(), &result);
            if (s != napi_ok) {
                WVLOG_E("JavaScriptOb FindMethod fail");
                return nullptr;
            }
            napi_typeof(env_, result, &valueType);
            if (valueType != napi_function) {
                return nullptr;
            }
            return result;
        }

        return nullptr;
    }

    void SetUpMethods()
    {
        napi_value propertyNames;
        napi_value obj = GetValue();
        napi_status s = napi_get_property_names(env_, obj, &propertyNames);
        if (s != napi_ok) {
            WVLOG_E("JavaScriptOb SetUpMethods fail");
            return;
        }
        size_t size;
        s = napi_get_array_length(env_, propertyNames, &size);
        if (s != napi_ok) {
            WVLOG_E("JavaScriptOb SetUpMethods fail");
            return;
        }
        for (size_t i = 0; i < size; i++) {
            napi_value napiKeyTmp;
            s = napi_get_element(env_, propertyNames, i, &napiKeyTmp);
            if (s != napi_ok) {
                WVLOG_E("JavaScriptOb SetUpMethods fail");
                return;
            }
            bool hasOwnProperty = false;
            s = napi_has_own_property(env_, obj, napiKeyTmp, &hasOwnProperty);
            if (s != napi_ok) {
                WVLOG_E("JavaScriptOb SetUpMethods fail");
                return;
            }
            if (!hasOwnProperty) {
                continue;
            }
            napi_valuetype valueType = napi_undefined;
            napi_value napiValueTmp;
            s = napi_get_property(env_, obj, napiKeyTmp, &napiValueTmp);
            if (s != napi_ok) {
                WVLOG_E("JavaScriptOb SetUpMethods fail");
                return;
            }
            napi_typeof(env_, napiValueTmp, &valueType);
            if (valueType != napi_function) {
                continue;
            }
            std::string methodName;
            if (NapiParseUtils::ParseString(env_, napiKeyTmp, methodName)) {
                std::unique_lock<std::mutex> lock(mutex);
                methods_.push_back(methodName);
            }
        }
        std::unique_lock<std::mutex> lock(mutex);
        isMethodsSetup_ = true;
    }

    void SetMethods(std::vector<std::string> methods_name)
    {
        std::unique_lock<std::mutex> lock(mutex);
        methods_ = methods_name;
        isMethodsSetup_ = true;
    }

private:
    static napi_status CreateNewWeakRef(napi_env env, napi_ref ref, napi_ref* new_ref)
    {
        napi_value val = nullptr;
        napi_status sts = napi_get_reference_value(env, ref, &val);
        if (sts != napi_ok)
            return sts;
        return napi_create_reference(env, val, 0, new_ref);
    }

    void Delete()
    {
        if (obj_ref_ && Release() == 0) {
            WVLOG_D("JavaScriptOb delete called");
            napi_delete_reference(env_, obj_ref_);
            obj_ref_ = nullptr;
        }
    }

    uint32_t Release()
    {
        if (!obj_ref_ || !isStrongRef_) {
            return 0;
        }
        uint32_t refCount = 0;
        napi_status s = napi_reference_unref(env_, obj_ref_, &refCount);
        if (s != napi_ok) {
            WVLOG_E("JavaScriptOb Release fail");
        }
        return refCount;
    }

    napi_env env_ = nullptr;
    napi_ref obj_ref_ = nullptr;
    bool isStrongRef_ = true;

    std::vector<std::string> methods_;
    // An object must be kept in retainedObjectSet_ either if it has
    // names or if it has a non-empty holders set.
    int namesCount_;
    std::set<int32_t> holders_;
    bool isMethodsSetup_ = false;
    std::mutex mutex;
};

class WebviewJavaScriptResultCallBack : public NWebJavaScriptResultCallBack {
public:
    typedef std::unordered_map<std::string, JavaScriptOb::ObjectID> NamedObjectMap;
    typedef std::unordered_map<JavaScriptOb::ObjectID, std::shared_ptr<JavaScriptOb>> ObjectMap;
    typedef int32_t ObjectID;
    WebviewJavaScriptResultCallBack() {}

    ~WebviewJavaScriptResultCallBack() override;

    std::shared_ptr<NWebValue> GetJavaScriptResult(std::vector<std::shared_ptr<NWebValue>> args,
        const std::string& method, const std::string& objName, int32_t routingId, int32_t objectId) override;

    bool HasJavaScriptObjectMethods(int32_t objectId, const std::string& methodName) override;

    std::shared_ptr<NWebValue> GetJavaScriptObjectMethods(int32_t objectId) override;

    std::shared_ptr<JavaScriptOb> FindObject(JavaScriptOb::ObjectID objectId);

    void RemoveJavaScriptObjectHolder(int32_t holder, JavaScriptOb::ObjectID objectId) override;

    void RemoveTransientJavaScriptObject() override;

    bool FindObjectId(napi_env env, napi_value object, JavaScriptOb::ObjectID* objectId);

    std::unordered_map<std::string, std::shared_ptr<JavaScriptOb>> GetObjects();

    JavaScriptOb::ObjectID RegisterJavaScriptProxy(
        napi_env env, napi_value obj, const std::string& objName, const std::vector<std::string>& methodList);

    bool DeleteJavaScriptRegister(const std::string& objName);

private:
    JavaScriptOb::ObjectID nextObjectId_ = 1;
    NamedObjectMap namedObjects_;
    ObjectMap objects_;
    std::unordered_set<std::shared_ptr<JavaScriptOb>> retainedObjectSet_;
    std::mutex objectMtx_;
    struct NapiJsCallBackParm {
        napi_env env;
        napi_value callback;
        std::shared_ptr<JavaScriptOb> object;
        std::vector<std::shared_ptr<NWebValue>> args;
        ObjectMap objectsMap;
        std::shared_ptr<NWebValue> value;
        std::mutex mutex;
        std::condition_variable condition;
        bool ready = false;
        bool isObject = false;
    };

    static void ParseNwebValue2NapiValue(napi_env env, std::shared_ptr<OHOS::NWeb::NWebValue> value,
        std::vector<napi_value>& argv, ObjectMap& objectsMap);

    static void ParseNapiValue2NwebValue(
        napi_env env, napi_value value, std::shared_ptr<NWebValue> nwebValue, bool* isObject);

    static void UvJsCallbackThreadWoker(uv_work_t* work, int status);

    void GetJavaScriptResultInner(napi_env env, int32_t routingId,
        WebviewJavaScriptResultCallBack::NapiJsCallBackParm* param, const std::string& method,
        std::shared_ptr<NWebValue>& ret);

    bool RemoveNamedObject(const std::string& name);

    JavaScriptOb::ObjectID AddNamedObject(napi_env env, napi_value& obj, const std::string& objName);

    JavaScriptOb::ObjectID AddObject(napi_env env, const napi_value& object, bool methodName, int32_t holder);
};
}
#endif
