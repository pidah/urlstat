package stat

import (
	"fmt"
	"strings"
)

type Response struct {
	Log []string

	// number of redirects followed
	redirectsFollowed int
}

func (r Response) String() string {
	return strings.Join(r.Log, "\n")
}

func (r *Response) report(format string, argv ...interface{}) {
	r.Log = append(r.Log, fmt.Sprintf(format, argv...))
}
