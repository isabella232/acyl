// Automatically generated by MockGen. DO NOT EDIT!
// Source: github.com/dollarshaveclub/furan/lib/squasher (interfaces: ImageSquasher)

package mocks

import (
	squasher "github.com/dollarshaveclub/furan/lib/squasher"
	context "golang.org/x/net/context"
	gomock "github.com/golang/mock/gomock"
	io "io"
)

// Mock of ImageSquasher interface
type MockImageSquasher struct {
	ctrl     *gomock.Controller
	recorder *_MockImageSquasherRecorder
}

// Recorder for MockImageSquasher (not exported)
type _MockImageSquasherRecorder struct {
	mock *MockImageSquasher
}

func NewMockImageSquasher(ctrl *gomock.Controller) *MockImageSquasher {
	mock := &MockImageSquasher{ctrl: ctrl}
	mock.recorder = &_MockImageSquasherRecorder{mock}
	return mock
}

func (_m *MockImageSquasher) EXPECT() *_MockImageSquasherRecorder {
	return _m.recorder
}

func (_m *MockImageSquasher) Squash(_param0 context.Context, _param1 io.Reader, _param2 io.Writer) (*squasher.SquashInfo, error) {
	ret := _m.ctrl.Call(_m, "Squash", _param0, _param1, _param2)
	ret0, _ := ret[0].(*squasher.SquashInfo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockImageSquasherRecorder) Squash(arg0, arg1, arg2 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Squash", arg0, arg1, arg2)
}