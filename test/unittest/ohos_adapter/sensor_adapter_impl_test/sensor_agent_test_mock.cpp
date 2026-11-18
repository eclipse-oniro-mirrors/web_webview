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

#include "sensor_agent.h"

#include <cstdint>

namespace {
constexpr int32_t DEFAULT_MOCK_SENSOR_COUNT = 8;
constexpr int64_t MOCK_MIN_SAMPLE_PERIOD = 5000000;   // 5 ms, maps to 200 Hz max frequency
constexpr int64_t MOCK_MAX_SAMPLE_PERIOD = 200000000;  // 200 ms, maps to 5 Hz min frequency
const int32_t DEFAULT_MOCK_SENSOR_TYPE_IDS[DEFAULT_MOCK_SENSOR_COUNT] = {
    SENSOR_TYPE_ID_ACCELEROMETER,
    SENSOR_TYPE_ID_GYROSCOPE,
    SENSOR_TYPE_ID_MAGNETIC_FIELD,
    SENSOR_TYPE_ID_ORIENTATION,
    SENSOR_TYPE_ID_GRAVITY,
    SENSOR_TYPE_ID_LINEAR_ACCELERATION,
    SENSOR_TYPE_ID_ROTATION_VECTOR,
    SENSOR_TYPE_ID_GAME_ROTATION_VECTOR,
};

SensorInfo g_defaultSensorList[DEFAULT_MOCK_SENSOR_COUNT];
bool g_defaultSensorListInitialized = false;

void InitDefaultSensorList()
{
    if (g_defaultSensorListInitialized) {
        return;
    }
    for (int32_t i = 0; i < DEFAULT_MOCK_SENSOR_COUNT; i++) {
        g_defaultSensorList[i] = SensorInfo{};
        g_defaultSensorList[i].sensorTypeId = DEFAULT_MOCK_SENSOR_TYPE_IDS[i];
        g_defaultSensorList[i].sensorId = DEFAULT_MOCK_SENSOR_TYPE_IDS[i];
        g_defaultSensorList[i].minSamplePeriod = MOCK_MIN_SAMPLE_PERIOD;
        g_defaultSensorList[i].maxSamplePeriod = MOCK_MAX_SAMPLE_PERIOD;
    }
    g_defaultSensorListInitialized = true;
}
} // namespace

// Configurable mock results shared with sensor_adapter_impl_test.cpp.
// Defaults keep the behaviour expected by the legacy test cases.
int32_t g_subscribeSensorRet = 0;      // SENSOR_SUCCESS
int32_t g_setBatchRet = 0;             // SENSOR_SUCCESS
int32_t g_activateSensorRet = 0;       // SENSOR_SUCCESS
int32_t g_setModeRet = 0;              // SENSOR_SUCCESS
int32_t g_deactivateSensorRet = -1;    // failure, same as without a real subscription
int32_t g_unsubscribeSensorRet = -1;   // failure, same as without a real subscription
int32_t g_getAllSensorsRet = 0;        // SENSOR_SUCCESS
int32_t g_sensorInfoCount = DEFAULT_MOCK_SENSOR_COUNT;
SensorInfo* g_sensorInfoList = g_defaultSensorList;

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

int32_t SubscribeSensor(int32_t sensorTypeId, const SensorUser *user)
{
    return g_subscribeSensorRet;
}

int32_t SetBatch(int32_t sensorTypeId, const SensorUser *user, int64_t samplingInterval, int64_t reportInterval)
{
    return g_setBatchRet;
}

int32_t ActivateSensor(int32_t sensorTypeId, const SensorUser *user)
{
    return g_activateSensorRet;
}

int32_t SetMode(int32_t sensorTypeId, const SensorUser *user, int32_t mode)
{
    return g_setModeRet;
}

int32_t DeactivateSensor(int32_t sensorTypeId, const SensorUser *user)
{
    return g_deactivateSensorRet;
}

int32_t UnsubscribeSensor(int32_t sensorTypeId, const SensorUser *user)
{
    return g_unsubscribeSensorRet;
}

int32_t GetAllSensors(SensorInfo **sensorInfo, int32_t *count)
{
    InitDefaultSensorList();
    if (sensorInfo != nullptr) {
        *sensorInfo = g_sensorInfoList;
    }
    if (count != nullptr) {
        *count = g_sensorInfoCount;
    }
    return g_getAllSensorsRet;
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
