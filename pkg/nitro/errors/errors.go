package errors

import "errors"

type UserError struct {
	error
}

func (err UserError) Error() string {
	return err.error.Error()
}

func (err UserError) Unwrap() error {
	return err.error
}

func User(err error) error {
	if err == nil {
		return nil
	}
	return UserError{err}
}

func IsUserError(err error) bool {
	return errors.As(err, &UserError{})
}

type CancelledError struct {
	error
}

func (err CancelledError) Error() string {
	return err.error.Error()
}

func (err CancelledError) Unwrap() error {
	return err.error
}

func Cancelled(err error) error {
	if err == nil {
		return nil
	}
	return CancelledError{err}
}

func IsCancelledError(err error) bool {
	return errors.As(err, &CancelledError{})
}

func IsSystemError(err error) bool {
	return !errors.As(err, &UserError{})
}
