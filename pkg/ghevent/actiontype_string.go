// Code generated by "stringer -type=ActionType"; DO NOT EDIT.

package ghevent

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[NotRelevant-0]
	_ = x[CreateNew-1]
	_ = x[Update-2]
	_ = x[Destroy-3]
}

const _ActionType_name = "NotRelevantCreateNewUpdateDestroy"

var _ActionType_index = [...]uint8{0, 11, 20, 26, 33}

func (i ActionType) String() string {
	if i < 0 || i >= ActionType(len(_ActionType_index)-1) {
		return "ActionType(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _ActionType_name[_ActionType_index[i]:_ActionType_index[i+1]]
}
