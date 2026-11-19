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

#ifndef SENSOR_AGENT_TEST_MOCK_H
#define SENSOR_AGENT_TEST_MOCK_H

#include <cstdint>
#include <string>

#include "sensor_agent.h"

namespace OHOS {
namespace NWeb {
// Controls the results returned by the sensor_agent mock implemented in
// sensor_agent_test_mock.cpp. Getters read the current mock state so tests
// can save it, setters change it and restore it afterwards.
class SensorAgentTestMock {
public:
    static int32_t GetSubscribeSensorResult();
    static void SetSubscribeSensorResult(int32_t result);

    static int32_t GetSetBatchResult();
    static void SetSetBatchResult(int32_t result);

    static int32_t GetActivateSensorResult();
    static void SetActivateSensorResult(int32_t result);

    static int32_t GetSetModeResult();
    static void SetSetModeResult(int32_t result);

    static int32_t GetDeactivateSensorResult();
    static void SetDeactivateSensorResult(int32_t result);

    static int32_t GetUnsubscribeSensorResult();
    static void SetUnsubscribeSensorResult(int32_t result);

    static int32_t GetGetAllSensorsResult();
    static void SetGetAllSensorsResult(int32_t result);

    static int32_t GetSensorInfoCount();
    static void SetSensorInfoCount(int32_t count);

    static SensorInfo* GetSensorInfoList();
    static void SetSensorInfoList(SensorInfo* list);
};

// Adapter-internal helpers defined in sensor_adapter_impl.cpp. They are not
// declared in sensor_adapter_impl.h, so they are declared here to avoid
// extern declarations inside the test source file.
SensorTypeId SensorTypeToOhosSensorType(int sensorTypeId);
std::string SensorTypeToSensorUserName(int sensorTypeId);
} // namespace NWeb
} // namespace OHOS

#endif // SENSOR_AGENT_TEST_MOCK_H
