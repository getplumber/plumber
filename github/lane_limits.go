package github

import (
	"regexp"
	"strconv"

	"github.com/sirupsen/logrus"
)

// maxLanePages bounds how many pages an optional lane (the environments
// and workflow-states listings) reads: a listing still answering a next
// page after this many is not walked further, and the lane answers
// unknown, the list it holds not being the whole one.
const maxLanePages = 20

// maxDefaultTokenJobsCalls bounds how many eligible runs the default
// token's log route asks for their jobs before giving up: an answer
// worth reading sits on one of the first runs, and this lane must stay
// cheap on a busy repository.
const maxDefaultTokenJobsCalls = 3

// httpStatusInError reads the HTTP status off a REST error message
// ("HTTP 403: ..."), the same best-effort shape isUnauthorized and
// isNotFound match on.
var httpStatusInError = regexp.MustCompile(`HTTP (\d{3})`)

// logRefusedLane records, at Info, that the API refused an optional lane
// (401, 403, 404): the lane's name and the status, so an operator can see
// why its facts stay unknown. Nothing else of err is logged (the request
// carries the token in its headers, never in the message, but the
// message is not needed either). An err that is not a refusal logs
// nothing.
func logRefusedLane(lane string, err error) {
	if !isUnauthorized(err) && !isNotFound(err) {
		return
	}
	status := 0
	if m := httpStatusInError.FindStringSubmatch(err.Error()); m != nil {
		status, _ = strconv.Atoi(m[1])
	}
	logrus.WithField("context", "collector").
		WithField("lane", lane).
		WithField("status", status).
		Info("optional GitHub lane refused, its facts stay unknown")
}
