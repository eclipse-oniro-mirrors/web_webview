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

#include <limits>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "sensor_agent_test_mock.h"

#define private public
#include "sensor_adapter.h"
#include "sensor_adapter_impl.h"
#undef private

using namespace testing;
using namespace testing::ext;

namespace OHOS::NWeb {

namespace {
std::shared_ptr<OHOS::NWeb::SensorCallbackImpl> g_sensoCallback;
std::shared_ptr<OHOS::NWeb::SensorAdapterImpl> g_sensorAdapter;
}
constexpr double NANOSECONDS_IN_SECOND = 1000000000.0;
constexpr double DEFAULT_SAMPLE_PERIOD = 200000000.0;

class SensorCallbackImplTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

class SensorAdapterImplTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

class SensorCallbackAdapterMock : public SensorCallbackAdapter {
public:
    ~SensorCallbackAdapterMock() = default;
    void UpdateOhosSensorData(double timestamp,
        double value1, double value2, double value3, double value4) {}
};

class RecordingSensorCallbackAdapter : public SensorCallbackAdapter {
public:
    void UpdateOhosSensorData(double timestamp,
        double value1, double value2, double value3, double value4) override
    {
        ++callCount;
        lastTimestamp = timestamp;
        lastValue1 = value1;
        lastValue2 = value2;
        lastValue3 = value3;
        lastValue4 = value4;
    }

    int32_t callCount = 0;
    double lastTimestamp = 0.0;
    double lastValue1 = 0.0;
    double lastValue2 = 0.0;
    double lastValue3 = 0.0;
    double lastValue4 = 0.0;
};

void SensorCallbackImplTest::SetUpTestCase(void) {}

void SensorCallbackImplTest::TearDownTestCase(void) {}

void SensorCallbackImplTest::SetUp(void)
{
    auto callbackAdapter = std::make_shared<SensorCallbackAdapterMock>();
    g_sensoCallback = std::make_shared<SensorCallbackImpl>(callbackAdapter);
    ASSERT_NE(g_sensoCallback, nullptr);
}

void SensorCallbackImplTest::TearDown(void)
{
    g_sensoCallback = nullptr;
}

void SensorAdapterImplTest::SetUpTestCase(void) {}

void SensorAdapterImplTest::TearDownTestCase(void) {}

void SensorAdapterImplTest::SetUp(void)
{
    g_sensorAdapter = std::make_shared<SensorAdapterImpl>();
    ASSERT_NE(g_sensorAdapter, nullptr);
}

void SensorAdapterImplTest::TearDown(void)
{
    g_sensorAdapter = nullptr;
}

/**
 * @tc.name: SensorAdapterImplTest_SensorCallbackImpl_001.
 * @tc.desc: test of SensorCallbackImpl :: UpdateOhosSensorData()
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(SensorCallbackImplTest, SensorAdapterImplTest_SensorCallbackImplTest_001, TestSize.Level1)
{
    double temp = 1.1;
    g_sensoCallback->callbackAdapter_ = nullptr;
    g_sensoCallback->UpdateOhosSensorData(temp, temp, temp, temp, temp);
    EXPECT_EQ(g_sensoCallback->callbackAdapter_, nullptr);

    auto callbackAdapter = std::make_shared<SensorCallbackAdapterMock>();
    g_sensoCallback->callbackAdapter_ = callbackAdapter;
    g_sensoCallback->UpdateOhosSensorData(temp, temp, temp, temp, temp);
    EXPECT_NE(g_sensoCallback->callbackAdapter_, nullptr);
}

/**
 * @tc.name: SensorAdapterImplTest_SensorAdapterImpl_001.
 * @tc.desc: test of SensorAdapterImpl :: IsOhosSensorSupported()
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, SensorAdapterImplTest_SensorAdapterImpl_001, TestSize.Level1)
{
    int32_t temp = 1;
    auto number = g_sensorAdapter->IsOhosSensorSupported(temp);
    EXPECT_EQ(number, SENSOR_ERROR);

    temp = 9;
    g_sensorAdapter->IsOhosSensorSupported(temp);
}

/**
 * @tc.name: SensorAdapterImplTest_SensorAdapterImpl_002.
 * @tc.desc: test of SensorAdapterImpl :: GetOhosSensorReportingMode()
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, SensorAdapterImplTest_SensorAdapterImpl_002, TestSize.Level1)
{
    int32_t temp = 11;
    int32_t temp1 = SENSOR_DATA_REPORT_CONTINUOUS;
    auto mode = g_sensorAdapter->GetOhosSensorReportingMode(temp);
    EXPECT_EQ(mode, temp1);

    temp = 1;
    temp1 = -1;
    mode = g_sensorAdapter->GetOhosSensorReportingMode(temp);
    EXPECT_EQ(mode, temp1);
}

/**
 * @tc.name: SensorAdapterImplTest_SensorAdapterImpl_003.
 * @tc.desc: test of SensorAdapterImpl :: GetOhosSensorDefaultSupportedFrequency()
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, SensorAdapterImplTest_SensorAdapterImpl_003, TestSize.Level1)
{
    int32_t temp = 1;
    double temp1 = 0.0;
    auto mode = g_sensorAdapter->GetOhosSensorDefaultSupportedFrequency(temp);
    EXPECT_EQ(mode, temp1);

    temp = 2;
    temp1 = NANOSECONDS_IN_SECOND / DEFAULT_SAMPLE_PERIOD;
    mode = g_sensorAdapter->GetOhosSensorDefaultSupportedFrequency(temp);
    EXPECT_EQ(mode, temp1);
}

/**
 * @tc.name: SensorAdapterImplTest_SensorAdapterImpl_004.
 * @tc.desc: test of SensorAdapterImpl :: GetOhosSensorMinSupportedFrequency()
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, SensorAdapterImplTest_SensorAdapterImpl_004, TestSize.Level1)
{
    int32_t temp = 1;
    double temp1 = 0.0;
    auto mode = g_sensorAdapter->GetOhosSensorMinSupportedFrequency(temp);
    EXPECT_EQ(mode, temp1);

    temp = 2;
    mode = g_sensorAdapter->GetOhosSensorMinSupportedFrequency(temp);
    EXPECT_NE(mode, temp1);    
}

/**
 * @tc.name: SensorAdapterImplTest_SensorAdapterImpl_005.
 * @tc.desc: test of SensorAdapterImpl :: GetOhosSensorMaxSupportedFrequency()
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, SensorAdapterImplTest_SensorAdapterImpl_005, TestSize.Level1)
{
    int32_t temp = 1;
    double temp1 = 0.0;
    auto mode = g_sensorAdapter->GetOhosSensorMaxSupportedFrequency(temp);
    EXPECT_EQ(mode, temp1);

    temp = 2;
    mode = g_sensorAdapter->GetOhosSensorMaxSupportedFrequency(temp);
    EXPECT_NE(mode, temp1);    
}

/**
 * @tc.name: SensorAdapterImplTest_SensorAdapterImpl_006.
 * @tc.desc: test of SensorAdapterImpl :: SubscribeOhosSensor()
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, SensorAdapterImplTest_SensorAdapterImpl_006, TestSize.Level1)
{
    int32_t id = 1;
    int64_t temp = 0;
    auto status = g_sensorAdapter->SubscribeOhosSensor(id, temp);
    EXPECT_EQ(status, SENSOR_PARAMETER_ERROR);

    temp = 1;
    status = g_sensorAdapter->SubscribeOhosSensor(id, temp);
    EXPECT_EQ(status, SENSOR_PARAMETER_ERROR);

    id = 2;
    status = g_sensorAdapter->SubscribeOhosSensor(id, temp);
    EXPECT_EQ(status, SENSOR_SUCCESS);
}

/**
 * @tc.name: SensorAdapterImplTest_SensorAdapterImpl_007.
 * @tc.desc: test of SensorAdapterImpl :: RegistOhosSensorCallback()
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, SensorAdapterImplTest_SensorAdapterImpl_007, TestSize.Level1)
{
    int32_t id = 1;
    auto callbackAdapter = std::make_shared<SensorCallbackAdapterMock>();
    auto status = g_sensorAdapter->RegistOhosSensorCallback(id, callbackAdapter);
    EXPECT_EQ(status, SENSOR_PARAMETER_ERROR);

    id = 2;
    status = g_sensorAdapter->RegistOhosSensorCallback(id, callbackAdapter);
    EXPECT_EQ(status, SENSOR_SUCCESS);
}

/**
 * @tc.name: SensorAdapterImplTest_SensorAdapterImpl_008.
 * @tc.desc: test of SensorAdapterImpl :: UnsubscribeOhosSensor()
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, SensorAdapterImplTest_SensorAdapterImpl_008, TestSize.Level1)
{
    int32_t id = 1;
    auto status = g_sensorAdapter->UnsubscribeOhosSensor(id);
    EXPECT_EQ(status, SENSOR_PARAMETER_ERROR);

    id = 2;
    status = g_sensorAdapter->UnsubscribeOhosSensor(id);
    EXPECT_NE(status, SENSOR_SUCCESS);
}


/**
 * @tc.name: SensorAdapterImplTest_SensorAdapterImpl_009.
 * @tc.desc: test of SensorAdapterImpl :: OhosSensorCallback()
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, SensorAdapterImplTest_SensorAdapterImpl_009, TestSize.Level1)
{
    std::vector<std::shared_ptr<OHOS::NWeb::SensorCallbackImpl>> callback(9);
    for(int32_t i=0; i<9; i++) {
        auto callbackAdapter = std::make_shared<SensorCallbackAdapterMock>();
        callback[i] = std::make_shared<OHOS::NWeb::SensorCallbackImpl>(callbackAdapter);
        SensorAdapterImpl::sensorCallbackMap.emplace(i+2,callback[i]);
    }

    SensorEvent* event = new SensorEvent;
    uint8_t *data = new uint8_t[10];
    event->data = data;
    g_sensorAdapter->OhosSensorCallback(event);
    event->sensorTypeId = 7;
    g_sensorAdapter->OhosSensorCallback(event);
    event->sensorTypeId = 2;
    g_sensorAdapter->OhosSensorCallback(event);
    event->sensorTypeId = 3;
    g_sensorAdapter->OhosSensorCallback(event);
    event->sensorTypeId = 4;
    g_sensorAdapter->OhosSensorCallback(event);
    event->sensorTypeId = 5;
    g_sensorAdapter->OhosSensorCallback(event);
    event->sensorTypeId = 6;
    g_sensorAdapter->OhosSensorCallback(event);
    event->sensorTypeId = 8;
    g_sensorAdapter->OhosSensorCallback(event);
    event->sensorTypeId = 9;
    g_sensorAdapter->OhosSensorCallback(event);
    event->sensorTypeId = 11;
    g_sensorAdapter->OhosSensorCallback(event);
    EXPECT_NE(g_sensorAdapter, nullptr);
    delete event;
    SensorAdapterImpl::sensorCallbackMap.clear();
}

/**
 * @tc.name: SensorAdapterImplTest_SensorAdapterImpl_010.
 * @tc.desc: test of SensorAdapterImpl :: handleAccelerometerData()
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, SensorAdapterImplTest_SensorAdapterImpl_010, TestSize.Level1)
{
    auto callbackAdapter = std::make_shared<SensorCallbackAdapterMock>();
    auto callback = std::make_shared<OHOS::NWeb::SensorCallbackImpl>(callbackAdapter);
    SensorEvent* event = new SensorEvent;
    g_sensorAdapter->handleAccelerometerData(callback, event);
    EXPECT_NE(g_sensorAdapter, nullptr);

    uint8_t *data = new uint8_t[10];
    event->data = data;
    g_sensorAdapter->handleAccelerometerData(callback, event);
    delete event->data;
    EXPECT_NE(g_sensorAdapter, nullptr);

    delete event;
    event =nullptr;
    g_sensorAdapter->handleAccelerometerData(callback, event);
    EXPECT_NE(g_sensorAdapter, nullptr);

    event = new SensorEvent;
    callback = nullptr;
    g_sensorAdapter->handleAccelerometerData(callback, event);
    EXPECT_NE(g_sensorAdapter, nullptr);

    delete event;
    event =nullptr;
    g_sensorAdapter->handleAccelerometerData(callback, event);
    EXPECT_NE(g_sensorAdapter, nullptr);
}
/**
 * @tc.name: SensorAdapterImplTest_SensorAdapterImpl_011.
 * @tc.desc: test of SensorAdapterImpl :: handleLinearAccelerometerData()
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, SensorAdapterImplTest_SensorAdapterImpl_011, TestSize.Level1)
{
    auto callbackAdapter = std::make_shared<SensorCallbackAdapterMock>();
    auto callback = std::make_shared<OHOS::NWeb::SensorCallbackImpl>(callbackAdapter);
    SensorEvent* event = new SensorEvent;
    g_sensorAdapter->handleLinearAccelerometerData(callback, event);
    EXPECT_NE(g_sensorAdapter, nullptr);

    uint8_t *data = new uint8_t[10];
    event->data = data;
    g_sensorAdapter->handleLinearAccelerometerData(callback, event);
    delete event->data;
    EXPECT_NE(g_sensorAdapter, nullptr);

    delete event;
    event =nullptr;
    g_sensorAdapter->handleLinearAccelerometerData(callback, event);
    EXPECT_NE(g_sensorAdapter, nullptr);

    event = new SensorEvent;
    callback = nullptr;
    g_sensorAdapter->handleLinearAccelerometerData(callback, event);
    EXPECT_NE(g_sensorAdapter, nullptr);

    delete event;
    event =nullptr;
    g_sensorAdapter->handleLinearAccelerometerData(callback, event);
    EXPECT_NE(g_sensorAdapter, nullptr);
}

/**
 * @tc.name: SensorAdapterImplTest_SensorAdapterImpl_012.
 * @tc.desc: test of SensorAdapterImpl :: handleGravityData()
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, SensorAdapterImplTest_SensorAdapterImpl_012, TestSize.Level1)
{
    auto callbackAdapter = std::make_shared<SensorCallbackAdapterMock>();
    auto callback = std::make_shared<OHOS::NWeb::SensorCallbackImpl>(callbackAdapter);
    SensorEvent* event = new SensorEvent;
    g_sensorAdapter->handleGravityData(callback, event);
    EXPECT_NE(g_sensorAdapter, nullptr);

    uint8_t *data = new uint8_t[10];
    event->data = data;
    g_sensorAdapter->handleGravityData(callback, event);
    delete event->data;
    EXPECT_NE(g_sensorAdapter, nullptr);

    delete event;
    event =nullptr;
    g_sensorAdapter->handleGravityData(callback, event);
    EXPECT_NE(g_sensorAdapter, nullptr);

    event = new SensorEvent;
    callback = nullptr;
    g_sensorAdapter->handleGravityData(callback, event);
    EXPECT_NE(g_sensorAdapter, nullptr);

    delete event;
    event =nullptr;
    g_sensorAdapter->handleGravityData(callback, event);
    EXPECT_NE(g_sensorAdapter, nullptr);
}

/**
 * @tc.name: SensorAdapterImplTest_SensorAdapterImpl_013.
 * @tc.desc: test of SensorAdapterImpl :: handleCyroscopeData()
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, SensorAdapterImplTest_SensorAdapterImpl_013, TestSize.Level1)
{
    auto callbackAdapter = std::make_shared<SensorCallbackAdapterMock>();
    auto callback = std::make_shared<OHOS::NWeb::SensorCallbackImpl>(callbackAdapter);
    SensorEvent* event = new SensorEvent;
    g_sensorAdapter->handleCyroscopeData(callback, event);
    EXPECT_NE(g_sensorAdapter, nullptr);

    uint8_t *data = new uint8_t[10];
    event->data = data;
    g_sensorAdapter->handleCyroscopeData(callback, event);
    delete event->data;
    EXPECT_NE(g_sensorAdapter, nullptr);

    delete event;
    event =nullptr;
    g_sensorAdapter->handleCyroscopeData(callback, event);
    EXPECT_NE(g_sensorAdapter, nullptr);

    event = new SensorEvent;
    callback = nullptr;
    g_sensorAdapter->handleCyroscopeData(callback, event);
    EXPECT_NE(g_sensorAdapter, nullptr);

    delete event;
    event =nullptr;
    g_sensorAdapter->handleCyroscopeData(callback, event);
    EXPECT_NE(g_sensorAdapter, nullptr);
}

/**
 * @tc.name: SensorAdapterImplTest_SensorAdapterImpl_014.
 * @tc.desc: test of SensorAdapterImpl :: handleMagnetometerData()
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, SensorAdapterImplTest_SensorAdapterImpl_014, TestSize.Level1)
{
    auto callbackAdapter = std::make_shared<SensorCallbackAdapterMock>();
    auto callback = std::make_shared<OHOS::NWeb::SensorCallbackImpl>(callbackAdapter);
    SensorEvent* event = new SensorEvent;
    g_sensorAdapter->handleMagnetometerData(callback, event);
    EXPECT_NE(g_sensorAdapter, nullptr);

    uint8_t *data = new uint8_t[10];
    event->data = data;
    g_sensorAdapter->handleMagnetometerData(callback, event);
    delete event->data;
    EXPECT_NE(g_sensorAdapter, nullptr);

    delete event;
    event =nullptr;
    g_sensorAdapter->handleMagnetometerData(callback, event);
    EXPECT_NE(g_sensorAdapter, nullptr);

    event = new SensorEvent;
    callback = nullptr;
    g_sensorAdapter->handleMagnetometerData(callback, event);
    EXPECT_NE(g_sensorAdapter, nullptr);

    delete event;
    event =nullptr;
    g_sensorAdapter->handleMagnetometerData(callback, event);
    EXPECT_NE(g_sensorAdapter, nullptr);
}

/**
 * @tc.name: SensorAdapterImplTest_SensorAdapterImpl_015.
 * @tc.desc: test of SensorAdapterImpl :: handleOrientationData()
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, SensorAdapterImplTest_SensorAdapterImpl_015, TestSize.Level1)
{
    auto callbackAdapter = std::make_shared<SensorCallbackAdapterMock>();
    auto callback = std::make_shared<OHOS::NWeb::SensorCallbackImpl>(callbackAdapter);
    SensorEvent* event = new SensorEvent;
    g_sensorAdapter->handleOrientationData(callback, event);
    EXPECT_NE(g_sensorAdapter, nullptr);

    uint8_t *data = new uint8_t[10];
    event->data = data;
    g_sensorAdapter->handleOrientationData(callback, event);
    delete event->data;
    EXPECT_NE(g_sensorAdapter, nullptr);

    delete event;
    event =nullptr;
    g_sensorAdapter->handleOrientationData(callback, event);
    EXPECT_NE(g_sensorAdapter, nullptr);

    event = new SensorEvent;
    callback = nullptr;
    g_sensorAdapter->handleOrientationData(callback, event);
    EXPECT_NE(g_sensorAdapter, nullptr);

    delete event;
    event =nullptr;
    g_sensorAdapter->handleOrientationData(callback, event);
    EXPECT_NE(g_sensorAdapter, nullptr);
}

/**
 * @tc.name: SensorAdapterImplTest_SensorAdapterImpl_016.
 * @tc.desc: test of SensorAdapterImpl :: handleRotationVectorData()
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, SensorAdapterImplTest_SensorAdapterImpl_016, TestSize.Level1)
{
    auto callbackAdapter = std::make_shared<SensorCallbackAdapterMock>();
    auto callback = std::make_shared<OHOS::NWeb::SensorCallbackImpl>(callbackAdapter);
    SensorEvent* event = new SensorEvent;
    g_sensorAdapter->handleRotationVectorData(callback, event);
    EXPECT_NE(g_sensorAdapter, nullptr);

    uint8_t *data = new uint8_t[10];
    event->data = data;
    g_sensorAdapter->handleRotationVectorData(callback, event);
    delete event->data;
    EXPECT_NE(g_sensorAdapter, nullptr);

    delete event;
    event =nullptr;
    g_sensorAdapter->handleRotationVectorData(callback, event);
    EXPECT_NE(g_sensorAdapter, nullptr);

    event = new SensorEvent;
    callback = nullptr;
    g_sensorAdapter->handleRotationVectorData(callback, event);
    EXPECT_NE(g_sensorAdapter, nullptr);

    delete event;
    event =nullptr;
    g_sensorAdapter->handleRotationVectorData(callback, event);
    EXPECT_NE(g_sensorAdapter, nullptr);
}

/**
 * @tc.name: SensorAdapterImplTest_SensorAdapterImpl_017.
 * @tc.desc: test of SensorAdapterImpl :: handleGameRotationVectorData()
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, SensorAdapterImplTest_SensorAdapterImpl_017, TestSize.Level1)
{
    auto callbackAdapter = std::make_shared<SensorCallbackAdapterMock>();
    auto callback = std::make_shared<OHOS::NWeb::SensorCallbackImpl>(callbackAdapter);
    SensorEvent* event = new SensorEvent;
    g_sensorAdapter->handleGameRotationVectorData(callback, event);
    EXPECT_NE(g_sensorAdapter, nullptr);

    uint8_t *data = new uint8_t[10];
    event->data = data;
    g_sensorAdapter->handleGameRotationVectorData(callback, event);
    delete event->data;
    EXPECT_NE(g_sensorAdapter, nullptr);

    delete event;
    event =nullptr;
    g_sensorAdapter->handleGameRotationVectorData(callback, event);
    EXPECT_NE(g_sensorAdapter, nullptr);

    event = new SensorEvent;
    callback = nullptr;
    g_sensorAdapter->handleGameRotationVectorData(callback, event);
    EXPECT_NE(g_sensorAdapter, nullptr);

    delete event;
    event =nullptr;
    g_sensorAdapter->handleGameRotationVectorData(callback, event);
    EXPECT_NE(g_sensorAdapter, nullptr);
}

/**
 * @tc.name: SensorTypeToOhosSensorType_001
 * @tc.desc: Verify web sensor type ids map to OH sensor type ids and invalid ids map to none
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, SensorTypeToOhosSensorType_001, TestSize.Level1)
{
    EXPECT_EQ(SensorTypeToOhosSensorType(2), SENSOR_TYPE_ID_ACCELEROMETER);
    EXPECT_EQ(SensorTypeToOhosSensorType(3), SENSOR_TYPE_ID_LINEAR_ACCELERATION);
    EXPECT_EQ(SensorTypeToOhosSensorType(4), SENSOR_TYPE_ID_GRAVITY);
    EXPECT_EQ(SensorTypeToOhosSensorType(5), SENSOR_TYPE_ID_GYROSCOPE);
    EXPECT_EQ(SensorTypeToOhosSensorType(6), SENSOR_TYPE_ID_MAGNETIC_FIELD);
    EXPECT_EQ(SensorTypeToOhosSensorType(8), SENSOR_TYPE_ID_ORIENTATION);
    EXPECT_EQ(SensorTypeToOhosSensorType(9), SENSOR_TYPE_ID_ROTATION_VECTOR);
    EXPECT_EQ(SensorTypeToOhosSensorType(11), SENSOR_TYPE_ID_GAME_ROTATION_VECTOR);

    EXPECT_EQ(SensorTypeToOhosSensorType(0), SENSOR_TYPE_ID_NONE);
    EXPECT_EQ(SensorTypeToOhosSensorType(1), SENSOR_TYPE_ID_NONE);
    EXPECT_EQ(SensorTypeToOhosSensorType(-1), SENSOR_TYPE_ID_NONE);
}

/**
 * @tc.name: SensorTypeToSensorUserName_001
 * @tc.desc: Verify all mapped user names and the default name for unknown ids
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, SensorTypeToSensorUserName_001, TestSize.Level1)
{
    EXPECT_EQ(SensorTypeToSensorUserName(2), "OhosAccelerometerService");
    EXPECT_EQ(SensorTypeToSensorUserName(3), "OhosLinearAccelerometerService");
    EXPECT_EQ(SensorTypeToSensorUserName(4), "OhosGravityService");
    EXPECT_EQ(SensorTypeToSensorUserName(5), "OhosCyroscopeService");
    EXPECT_EQ(SensorTypeToSensorUserName(6), "OhosMagnetometerService");
    EXPECT_EQ(SensorTypeToSensorUserName(8), "OhosOrientationService");
    EXPECT_EQ(SensorTypeToSensorUserName(9), "OhosRotationVectorService");
    EXPECT_EQ(SensorTypeToSensorUserName(11), "OhosGameRotationVectorService");
    EXPECT_EQ(SensorTypeToSensorUserName(0), "OhosSensorService");
    EXPECT_EQ(SensorTypeToSensorUserName(7), "OhosSensorService");
}

/**
 * @tc.name: GetOhosSensorReportingMode_003
 * @tc.desc: Verify reporting mode for every supported sensor and an unsupported one
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, GetOhosSensorReportingMode_003, TestSize.Level1)
{
    const int32_t supportedIds[] = {2, 3, 4, 5, 6, 8, 9, 11};
    for (int32_t id : supportedIds) {
        EXPECT_EQ(g_sensorAdapter->GetOhosSensorReportingMode(id), SENSOR_DATA_REPORT_CONTINUOUS);
    }
    EXPECT_EQ(g_sensorAdapter->GetOhosSensorReportingMode(0), -1);
}

/**
 * @tc.name: GetOhosSensorDefaultSupportedFrequency_002
 * @tc.desc: Verify default frequency is 5Hz for supported ids and 0 for unsupported ids
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, GetOhosSensorDefaultSupportedFrequency_002, TestSize.Level1)
{
    EXPECT_DOUBLE_EQ(g_sensorAdapter->GetOhosSensorDefaultSupportedFrequency(0), 0.0);
    EXPECT_DOUBLE_EQ(g_sensorAdapter->GetOhosSensorDefaultSupportedFrequency(11),
        NANOSECONDS_IN_SECOND / DEFAULT_SAMPLE_PERIOD);
}

/**
 * @tc.name: GetOhosSensorMinSupportedFrequency_002
 * @tc.desc: Verify min supported frequency returns 0 for unsupported sensor ids
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, GetOhosSensorMinSupportedFrequency_002, TestSize.Level2)
{
    EXPECT_DOUBLE_EQ(g_sensorAdapter->GetOhosSensorMinSupportedFrequency(0), 0.0);
    EXPECT_DOUBLE_EQ(g_sensorAdapter->GetOhosSensorMinSupportedFrequency(-1), 0.0);
}

/**
 * @tc.name: GetOhosSensorMaxSupportedFrequency_002
 * @tc.desc: Verify max supported frequency returns 0 for unsupported sensor ids
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, GetOhosSensorMaxSupportedFrequency_002, TestSize.Level2)
{
    EXPECT_DOUBLE_EQ(g_sensorAdapter->GetOhosSensorMaxSupportedFrequency(0), 0.0);
    EXPECT_DOUBLE_EQ(g_sensorAdapter->GetOhosSensorMaxSupportedFrequency(1), 0.0);
}

/**
 * @tc.name: SubscribeOhosSensor_002
 * @tc.desc: Verify invalid sampling intervals and invalid sensor ids are rejected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, SubscribeOhosSensor_002, TestSize.Level2)
{
    EXPECT_EQ(g_sensorAdapter->SubscribeOhosSensor(2, -1), SENSOR_PARAMETER_ERROR);
    EXPECT_EQ(g_sensorAdapter->SubscribeOhosSensor(2, std::numeric_limits<int64_t>::min()), SENSOR_PARAMETER_ERROR);
    EXPECT_EQ(g_sensorAdapter->SubscribeOhosSensor(0, 1000), SENSOR_PARAMETER_ERROR);
}

/**
 * @tc.name: UpdateOhosSensorData_002
 * @tc.desc: Verify SensorCallbackImpl forwards all five data values to its adapter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SensorCallbackImplTest, UpdateOhosSensorData_002, TestSize.Level1)
{
    auto callbackAdapter = std::make_shared<RecordingSensorCallbackAdapter>();
    SensorCallbackImpl callback(callbackAdapter);

    callback.UpdateOhosSensorData(1.0, 2.0, 3.0, 4.0, 5.0);

    EXPECT_EQ(callbackAdapter->callCount, 1);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastTimestamp, 1.0);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue1, 2.0);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue2, 3.0);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue3, 4.0);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue4, 5.0);
}

/**
 * @tc.name: OhosSensorCallback_002
 * @tc.desc: Verify accelerometer event is dispatched with parsed values to registered callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, OhosSensorCallback_002, TestSize.Level1)
{
    SensorAdapterImpl::sensorCallbackMap.erase(SENSOR_TYPE_ID_ACCELEROMETER);
    auto callbackAdapter = std::make_shared<RecordingSensorCallbackAdapter>();
    ASSERT_EQ(g_sensorAdapter->RegistOhosSensorCallback(2, callbackAdapter), SENSOR_SUCCESS);
    ASSERT_EQ(SensorAdapterImpl::sensorCallbackMap.count(SENSOR_TYPE_ID_ACCELEROMETER), 1U);

    AccelData data;
    data.x = 1.0F;
    data.y = 2.0F;
    data.z = 3.0F;
    SensorEvent event;
    event.sensorTypeId = SENSOR_TYPE_ID_ACCELEROMETER;
    event.timestamp = 123;
    event.data = reinterpret_cast<uint8_t*>(&data);
    event.dataLen = sizeof(data);

    g_sensorAdapter->OhosSensorCallback(&event);

    EXPECT_EQ(callbackAdapter->callCount, 1);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastTimestamp, 123.0);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue1, 1.0);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue2, 2.0);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue3, 3.0);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue4, 0.0);

    SensorAdapterImpl::sensorCallbackMap.erase(SENSOR_TYPE_ID_ACCELEROMETER);
    g_sensorAdapter->OhosSensorCallback(&event);
    EXPECT_EQ(callbackAdapter->callCount, 1);
}

/**
 * @tc.name: HandleGameRotationVectorData_002
 * @tc.desc: Verify short data buffer is ignored and valid buffer forwards four values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, HandleGameRotationVectorData_002, TestSize.Level2)
{
    auto callbackAdapter = std::make_shared<RecordingSensorCallbackAdapter>();
    auto callback = std::make_shared<SensorCallbackImpl>(callbackAdapter);
    GameRotationVectorData data;
    data.x = 1.0F;
    data.y = 2.0F;
    data.z = 3.0F;
    data.w = 4.0F;
    SensorEvent event;
    event.sensorTypeId = SENSOR_TYPE_ID_GAME_ROTATION_VECTOR;
    event.data = reinterpret_cast<uint8_t*>(&data);

    event.dataLen = sizeof(data) - 1;
    g_sensorAdapter->handleGameRotationVectorData(callback, &event);
    EXPECT_EQ(callbackAdapter->callCount, 0);

    event.dataLen = sizeof(data);
    g_sensorAdapter->handleGameRotationVectorData(callback, &event);
    EXPECT_EQ(callbackAdapter->callCount, 1);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue1, 1.0);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue2, 2.0);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue3, 3.0);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue4, 4.0);
}

/**
 * @tc.name: IsOhosSensorSupported_002
 * @tc.desc: Verify all mapped sensor ids report supported and hidden ones report unsupported
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, IsOhosSensorSupported_002, TestSize.Level1)
{
    const int32_t supportedIds[] = {2, 3, 4, 5, 6, 8, 9, 11};
    for (int32_t id : supportedIds) {
        EXPECT_EQ(g_sensorAdapter->IsOhosSensorSupported(id), SENSOR_SUCCESS);
    }

    int32_t savedCount = SensorAgentTestMock::GetSensorInfoCount();
    SensorAgentTestMock::SetSensorInfoCount(1); // only the accelerometer entry is visible
    EXPECT_EQ(g_sensorAdapter->IsOhosSensorSupported(2), SENSOR_SUCCESS);
    EXPECT_EQ(g_sensorAdapter->IsOhosSensorSupported(5), SENSOR_ERROR);
    SensorAgentTestMock::SetSensorInfoCount(savedCount);
}

/**
 * @tc.name: IsOhosSensorSupported_003
 * @tc.desc: Verify GetAllSensors failures (error code, null list, negative count) map to SENSOR_ERROR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, IsOhosSensorSupported_003, TestSize.Level2)
{
    int32_t savedRet = SensorAgentTestMock::GetGetAllSensorsResult();
    int32_t savedCount = SensorAgentTestMock::GetSensorInfoCount();
    SensorInfo* savedList = SensorAgentTestMock::GetSensorInfoList();

    SensorAgentTestMock::SetGetAllSensorsResult(-1);
    EXPECT_EQ(g_sensorAdapter->IsOhosSensorSupported(2), SENSOR_ERROR);

    SensorAgentTestMock::SetGetAllSensorsResult(0);
    SensorAgentTestMock::SetSensorInfoList(nullptr);
    EXPECT_EQ(g_sensorAdapter->IsOhosSensorSupported(2), SENSOR_ERROR);

    SensorAgentTestMock::SetSensorInfoList(savedList);
    SensorAgentTestMock::SetSensorInfoCount(-1);
    EXPECT_EQ(g_sensorAdapter->IsOhosSensorSupported(2), SENSOR_ERROR);

    SensorAgentTestMock::SetGetAllSensorsResult(savedRet);
    SensorAgentTestMock::SetSensorInfoCount(savedCount);
    SensorAgentTestMock::SetSensorInfoList(savedList);
}

/**
 * @tc.name: GetOhosSensorMinSupportedFrequency_003
 * @tc.desc: Verify min frequency derives from maxSamplePeriod and stays 0 when absent or invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, GetOhosSensorMinSupportedFrequency_003, TestSize.Level1)
{
    int32_t savedCount = SensorAgentTestMock::GetSensorInfoCount();
    EXPECT_DOUBLE_EQ(g_sensorAdapter->GetOhosSensorMinSupportedFrequency(2), 5.0); // 1e9 / 2e8

    SensorAgentTestMock::GetSensorInfoList()[0].maxSamplePeriod = 0;
    EXPECT_DOUBLE_EQ(g_sensorAdapter->GetOhosSensorMinSupportedFrequency(2), 0.0);
    SensorAgentTestMock::GetSensorInfoList()[0].maxSamplePeriod = 200000000;

    SensorAgentTestMock::SetSensorInfoCount(0); // no sensor visible
    EXPECT_DOUBLE_EQ(g_sensorAdapter->GetOhosSensorMinSupportedFrequency(2), 0.0);
    SensorAgentTestMock::SetSensorInfoCount(savedCount);
}

/**
 * @tc.name: GetOhosSensorMaxSupportedFrequency_003
 * @tc.desc: Verify max frequency derives from minSamplePeriod and stays 0 when absent or invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, GetOhosSensorMaxSupportedFrequency_003, TestSize.Level1)
{
    int32_t savedCount = SensorAgentTestMock::GetSensorInfoCount();
    EXPECT_DOUBLE_EQ(g_sensorAdapter->GetOhosSensorMaxSupportedFrequency(2), 200.0); // 1e9 / 5e6

    SensorAgentTestMock::GetSensorInfoList()[0].minSamplePeriod = 0;
    EXPECT_DOUBLE_EQ(g_sensorAdapter->GetOhosSensorMaxSupportedFrequency(2), 0.0);
    SensorAgentTestMock::GetSensorInfoList()[0].minSamplePeriod = 5000000;

    SensorAgentTestMock::SetSensorInfoCount(0); // no sensor visible
    EXPECT_DOUBLE_EQ(g_sensorAdapter->GetOhosSensorMaxSupportedFrequency(2), 0.0);
    SensorAgentTestMock::SetSensorInfoCount(savedCount);
}

/**
 * @tc.name: SubscribeOhosSensor_003
 * @tc.desc: Verify failures of each native call are propagated and all mapped ids can subscribe
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, SubscribeOhosSensor_003, TestSize.Level2)
{
    int32_t savedSubscribeRet = SensorAgentTestMock::GetSubscribeSensorResult();
    int32_t savedSetBatchRet = SensorAgentTestMock::GetSetBatchResult();
    int32_t savedActivateRet = SensorAgentTestMock::GetActivateSensorResult();
    int32_t savedSetModeRet = SensorAgentTestMock::GetSetModeResult();

    SensorAgentTestMock::SetSubscribeSensorResult(-2);
    EXPECT_EQ(g_sensorAdapter->SubscribeOhosSensor(2, 1000000), -2);
    SensorAgentTestMock::SetSubscribeSensorResult(savedSubscribeRet);

    SensorAgentTestMock::SetSetBatchResult(-3);
    EXPECT_EQ(g_sensorAdapter->SubscribeOhosSensor(2, 1000000), -3);
    SensorAgentTestMock::SetSetBatchResult(savedSetBatchRet);

    SensorAgentTestMock::SetActivateSensorResult(-4);
    EXPECT_EQ(g_sensorAdapter->SubscribeOhosSensor(2, 1000000), -4);
    SensorAgentTestMock::SetActivateSensorResult(savedActivateRet);

    SensorAgentTestMock::SetSetModeResult(-5);
    EXPECT_EQ(g_sensorAdapter->SubscribeOhosSensor(2, 1000000), -5);
    SensorAgentTestMock::SetSetModeResult(savedSetModeRet);

    const int32_t supportedIds[] = {2, 3, 4, 5, 6, 8, 9, 11};
    for (int32_t id : supportedIds) {
        EXPECT_EQ(g_sensorAdapter->SubscribeOhosSensor(id, 200000000), SENSOR_SUCCESS);
    }
}

/**
 * @tc.name: UnsubscribeOhosSensor_002
 * @tc.desc: Verify unsubscribe removes the callback on success and keeps it on native failures
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, UnsubscribeOhosSensor_002, TestSize.Level2)
{
    int32_t savedDeactivateRet = SensorAgentTestMock::GetDeactivateSensorResult();
    int32_t savedUnsubscribeRet = SensorAgentTestMock::GetUnsubscribeSensorResult();
    auto callbackAdapter = std::make_shared<SensorCallbackAdapterMock>();

    EXPECT_EQ(g_sensorAdapter->UnsubscribeOhosSensor(12), SENSOR_PARAMETER_ERROR);
    EXPECT_EQ(g_sensorAdapter->UnsubscribeOhosSensor(-1), SENSOR_PARAMETER_ERROR);

    EXPECT_EQ(g_sensorAdapter->RegistOhosSensorCallback(2, callbackAdapter), SENSOR_SUCCESS);
    ASSERT_EQ(SensorAdapterImpl::sensorCallbackMap.count(SENSOR_TYPE_ID_ACCELEROMETER), 1U);

    SensorAgentTestMock::SetDeactivateSensorResult(0);
    SensorAgentTestMock::SetUnsubscribeSensorResult(0);
    EXPECT_EQ(g_sensorAdapter->UnsubscribeOhosSensor(2), SENSOR_SUCCESS);
    EXPECT_EQ(SensorAdapterImpl::sensorCallbackMap.count(SENSOR_TYPE_ID_ACCELEROMETER), 0U);

    // DeactivateSensor failure keeps the registered callback.
    EXPECT_EQ(g_sensorAdapter->RegistOhosSensorCallback(2, callbackAdapter), SENSOR_SUCCESS);
    SensorAgentTestMock::SetDeactivateSensorResult(-1);
    EXPECT_EQ(g_sensorAdapter->UnsubscribeOhosSensor(2), -1);
    EXPECT_EQ(SensorAdapterImpl::sensorCallbackMap.count(SENSOR_TYPE_ID_ACCELEROMETER), 1U);

    // UnsubscribeSensor failure keeps the registered callback as well.
    SensorAgentTestMock::SetDeactivateSensorResult(0);
    SensorAgentTestMock::SetUnsubscribeSensorResult(-1);
    EXPECT_EQ(g_sensorAdapter->UnsubscribeOhosSensor(2), -1);
    EXPECT_EQ(SensorAdapterImpl::sensorCallbackMap.count(SENSOR_TYPE_ID_ACCELEROMETER), 1U);

    SensorAgentTestMock::SetDeactivateSensorResult(savedDeactivateRet);
    SensorAgentTestMock::SetUnsubscribeSensorResult(savedUnsubscribeRet);
    SensorAdapterImpl::sensorCallbackMap.erase(SENSOR_TYPE_ID_ACCELEROMETER);
}

/**
 * @tc.name: RegistOhosSensorCallback_002
 * @tc.desc: Verify duplicate registration overwrites the callback and invalid ids are rejected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, RegistOhosSensorCallback_002, TestSize.Level2)
{
    const int32_t supportedIds[] = {2, 3, 4, 5, 6, 8, 9, 11};
    auto callbackAdapter = std::make_shared<SensorCallbackAdapterMock>();
    for (int32_t id : supportedIds) {
        EXPECT_EQ(g_sensorAdapter->RegistOhosSensorCallback(id, callbackAdapter), SENSOR_SUCCESS);
    }
    EXPECT_EQ(static_cast<int32_t>(SensorAdapterImpl::sensorCallbackMap.size()), 8);

    // Duplicate registration overwrites instead of inserting a second entry.
    EXPECT_EQ(g_sensorAdapter->RegistOhosSensorCallback(2, callbackAdapter), SENSOR_SUCCESS);
    EXPECT_EQ(static_cast<int32_t>(SensorAdapterImpl::sensorCallbackMap.size()), 8);
    EXPECT_EQ(SensorAdapterImpl::sensorCallbackMap.count(SENSOR_TYPE_ID_ACCELEROMETER), 1U);

    // A null adapter is stored as-is by the adapter implementation.
    EXPECT_EQ(g_sensorAdapter->RegistOhosSensorCallback(4, nullptr), SENSOR_SUCCESS);
    EXPECT_EQ(SensorAdapterImpl::sensorCallbackMap.count(SENSOR_TYPE_ID_GRAVITY), 1U);

    EXPECT_EQ(g_sensorAdapter->RegistOhosSensorCallback(12, callbackAdapter), SENSOR_PARAMETER_ERROR);
    EXPECT_EQ(g_sensorAdapter->RegistOhosSensorCallback(-1, callbackAdapter), SENSOR_PARAMETER_ERROR);

    for (int32_t ohosId : {SENSOR_TYPE_ID_ACCELEROMETER, SENSOR_TYPE_ID_GYROSCOPE,
        SENSOR_TYPE_ID_MAGNETIC_FIELD, SENSOR_TYPE_ID_ORIENTATION, SENSOR_TYPE_ID_GRAVITY,
        SENSOR_TYPE_ID_LINEAR_ACCELERATION, SENSOR_TYPE_ID_ROTATION_VECTOR,
        SENSOR_TYPE_ID_GAME_ROTATION_VECTOR}) {
        SensorAdapterImpl::sensorCallbackMap.erase(ohosId);
    }
}

/**
 * @tc.name: OhosSensorCallback_003
 * @tc.desc: Verify null events and unregistered or unknown sensor types are ignored safely
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, OhosSensorCallback_003, TestSize.Level2)
{
    g_sensorAdapter->OhosSensorCallback(nullptr); // no crash

    SensorAdapterImpl::sensorCallbackMap.erase(SENSOR_TYPE_ID_GYROSCOPE);
    auto callbackAdapter = std::make_shared<RecordingSensorCallbackAdapter>();
    ASSERT_EQ(g_sensorAdapter->RegistOhosSensorCallback(2, callbackAdapter), SENSOR_SUCCESS);

    // A type with no registered callback is ignored.
    SensorEvent event;
    event.sensorTypeId = SENSOR_TYPE_ID_GYROSCOPE;
    event.timestamp = 111;
    event.data = nullptr;
    event.dataLen = 0;
    g_sensorAdapter->OhosSensorCallback(&event);
    EXPECT_EQ(callbackAdapter->callCount, 0);

    // A type that hits no dispatch branch does not forward data.
    SensorAdapterImpl::sensorCallbackMap[999] = std::make_shared<SensorCallbackImpl>(callbackAdapter);
    event.sensorTypeId = 999;
    g_sensorAdapter->OhosSensorCallback(&event);
    EXPECT_EQ(callbackAdapter->callCount, 0);
    SensorAdapterImpl::sensorCallbackMap.erase(999);

    SensorAdapterImpl::sensorCallbackMap.erase(SENSOR_TYPE_ID_ACCELEROMETER);
}

namespace {
// Sends one x/y/z sensor event through OhosSensorCallback. SensorData must
// have float members x, y and z, e.g. LinearAccelData or GravityData.
template <typename SensorData>
void DispatchThreeAxisSensorEvent(SensorAdapterImpl* adapter, int32_t sensorTypeId, float x, float y, float z)
{
    SensorData data;
    data.x = x;
    data.y = y;
    data.z = z;
    SensorEvent event;
    event.sensorTypeId = sensorTypeId;
    event.timestamp = 1234;
    event.data = reinterpret_cast<uint8_t*>(&data);
    event.dataLen = sizeof(data);
    adapter->OhosSensorCallback(&event);
}
} // namespace

/**
 * @tc.name: OhosSensorCallback_004
 * @tc.desc: Verify linear acceleration, gravity, gyroscope and magnetometer events forward x/y/z with 0 as 4th value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, OhosSensorCallback_004, TestSize.Level1)
{
    auto callbackAdapter = std::make_shared<RecordingSensorCallbackAdapter>();
    ASSERT_EQ(g_sensorAdapter->RegistOhosSensorCallback(3, callbackAdapter), SENSOR_SUCCESS);
    ASSERT_EQ(g_sensorAdapter->RegistOhosSensorCallback(4, callbackAdapter), SENSOR_SUCCESS);
    ASSERT_EQ(g_sensorAdapter->RegistOhosSensorCallback(5, callbackAdapter), SENSOR_SUCCESS);
    ASSERT_EQ(g_sensorAdapter->RegistOhosSensorCallback(6, callbackAdapter), SENSOR_SUCCESS);

    DispatchThreeAxisSensorEvent<LinearAccelData>(g_sensorAdapter.get(),
        SENSOR_TYPE_ID_LINEAR_ACCELERATION, 1.5F, 2.5F, 3.5F);
    EXPECT_EQ(callbackAdapter->callCount, 1);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastTimestamp, 1234.0);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue1, 1.5);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue2, 2.5);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue3, 3.5);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue4, 0.0);

    DispatchThreeAxisSensorEvent<GravityData>(g_sensorAdapter.get(), SENSOR_TYPE_ID_GRAVITY, 4.5F, 5.5F, 6.5F);
    EXPECT_EQ(callbackAdapter->callCount, 2);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue1, 4.5);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue2, 5.5);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue3, 6.5);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue4, 0.0);

    DispatchThreeAxisSensorEvent<GyroscopeData>(g_sensorAdapter.get(), SENSOR_TYPE_ID_GYROSCOPE, 7.5F, 8.5F, 9.5F);
    EXPECT_EQ(callbackAdapter->callCount, 3);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue1, 7.5);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue2, 8.5);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue3, 9.5);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue4, 0.0);

    DispatchThreeAxisSensorEvent<MagneticFieldData>(g_sensorAdapter.get(),
        SENSOR_TYPE_ID_MAGNETIC_FIELD, 10.5F, 11.5F, 12.5F);
    EXPECT_EQ(callbackAdapter->callCount, 4);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue1, 10.5);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue2, 11.5);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue3, 12.5);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue4, 0.0);

    SensorAdapterImpl::sensorCallbackMap.erase(SENSOR_TYPE_ID_LINEAR_ACCELERATION);
    SensorAdapterImpl::sensorCallbackMap.erase(SENSOR_TYPE_ID_GRAVITY);
    SensorAdapterImpl::sensorCallbackMap.erase(SENSOR_TYPE_ID_GYROSCOPE);
    SensorAdapterImpl::sensorCallbackMap.erase(SENSOR_TYPE_ID_MAGNETIC_FIELD);
}

/**
 * @tc.name: OhosSensorCallback_005
 * @tc.desc: Verify orientation forwards beta/gamma/alpha and rotation vector forwards x/y/z/w
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SensorAdapterImplTest, OhosSensorCallback_005, TestSize.Level1)
{
    auto callbackAdapter = std::make_shared<RecordingSensorCallbackAdapter>();
    ASSERT_EQ(g_sensorAdapter->RegistOhosSensorCallback(8, callbackAdapter), SENSOR_SUCCESS);
    ASSERT_EQ(g_sensorAdapter->RegistOhosSensorCallback(9, callbackAdapter), SENSOR_SUCCESS);

    SensorEvent event;
    event.timestamp = 99;
    OrientationData orientationData;
    orientationData.alpha = 30.0F;
    orientationData.beta = 60.0F;
    orientationData.gamma = 90.0F;
    event.sensorTypeId = SENSOR_TYPE_ID_ORIENTATION;
    event.data = reinterpret_cast<uint8_t*>(&orientationData);
    event.dataLen = sizeof(orientationData);
    g_sensorAdapter->OhosSensorCallback(&event);
    EXPECT_EQ(callbackAdapter->callCount, 1);
    // The adapter forwards beta, gamma, alpha in this order.
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue1, 60.0);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue2, 90.0);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue3, 30.0);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue4, 0.0);

    RotationVectorData rotationData;
    rotationData.x = 0.5F;
    rotationData.y = 1.5F;
    rotationData.z = 2.5F;
    rotationData.w = 3.5F;
    event.sensorTypeId = SENSOR_TYPE_ID_ROTATION_VECTOR;
    event.data = reinterpret_cast<uint8_t*>(&rotationData);
    event.dataLen = sizeof(rotationData);
    g_sensorAdapter->OhosSensorCallback(&event);
    EXPECT_EQ(callbackAdapter->callCount, 2);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue1, 0.5);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue2, 1.5);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue3, 2.5);
    EXPECT_DOUBLE_EQ(callbackAdapter->lastValue4, 3.5);

    SensorAdapterImpl::sensorCallbackMap.erase(SENSOR_TYPE_ID_ORIENTATION);
    SensorAdapterImpl::sensorCallbackMap.erase(SENSOR_TYPE_ID_ROTATION_VECTOR);
}
} // namespace OHOS::NWeb