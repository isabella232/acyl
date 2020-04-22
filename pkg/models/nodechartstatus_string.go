// Code generated by "stringer -type=NodeChartStatus"; DO NOT EDIT.

package models

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[UnknownChartStatus-0]
	_ = x[WaitingChartStatus-1]
	_ = x[InstallingChartStatus-2]
	_ = x[UpgradingChartStatus-3]
	_ = x[DoneChartStatus-4]
	_ = x[FailedChartStatus-5]
}

const _NodeChartStatus_name = "UnknownChartStatusWaitingChartStatusInstallingChartStatusUpgradingChartStatusDoneChartStatusFailedChartStatus"

var _NodeChartStatus_index = [...]uint8{0, 18, 36, 57, 77, 92, 109}

func (i NodeChartStatus) String() string {
	if i < 0 || i >= NodeChartStatus(len(_NodeChartStatus_index)-1) {
		return "NodeChartStatus(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _NodeChartStatus_name[_NodeChartStatus_index[i]:_NodeChartStatus_index[i+1]]
}