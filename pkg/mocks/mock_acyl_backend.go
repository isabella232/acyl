// Automatically generated by MockGen. DO NOT EDIT!
// Source: github.com/dollarshaveclub/acyl/pkg/spawner (interfaces: AcylBackend)

package mocks

import (
	context "context"
	models "github.com/dollarshaveclub/acyl/pkg/models"
	gomock "github.com/golang/mock/gomock"
)

// Mock of AcylBackend interface
type MockAcylBackend struct {
	ctrl     *gomock.Controller
	recorder *_MockAcylBackendRecorder
}

// Recorder for MockAcylBackend (not exported)
type _MockAcylBackendRecorder struct {
	mock *MockAcylBackend
}

func NewMockAcylBackend(ctrl *gomock.Controller) *MockAcylBackend {
	mock := &MockAcylBackend{ctrl: ctrl}
	mock.recorder = &_MockAcylBackendRecorder{mock}
	return mock
}

func (_m *MockAcylBackend) EXPECT() *_MockAcylBackendRecorder {
	return _m.recorder
}

func (_m *MockAcylBackend) CreateEnvironment(_param0 context.Context, _param1 *models.QAEnvironment, _param2 *models.QAType) (string, error) {
	ret := _m.ctrl.Call(_m, "CreateEnvironment", _param0, _param1, _param2)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockAcylBackendRecorder) CreateEnvironment(arg0, arg1, arg2 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "CreateEnvironment", arg0, arg1, arg2)
}

func (_m *MockAcylBackend) DestroyEnvironment(_param0 context.Context, _param1 *models.QAEnvironment, _param2 bool) error {
	ret := _m.ctrl.Call(_m, "DestroyEnvironment", _param0, _param1, _param2)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockAcylBackendRecorder) DestroyEnvironment(arg0, arg1, arg2 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "DestroyEnvironment", arg0, arg1, arg2)
}