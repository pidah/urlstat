package stat

import (
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func main() {
	r := NewRequest(os.Args[1])
	fmt.Println(Trace(r))
}

func makePanic(desc string, argv ...interface{}) {
	panic(fmt.Sprintf(desc, argv...))
}

func Trace(r *Request) *Response {
	if (r.HTTPMethod == "POST" || r.HTTPMethod == "PUT") && r.PostBody == "" {
		makePanic("Must supply post body using -d when POST or PUT is used")
	}

	if r.OnlyHeader {
		r.HTTPMethod = "HEAD"
	}

	resp := &Response{}
	r.visit(resp)
	return resp
}

// readClientCert - helper function to read client certificate
// from pem formatted file
func readClientCert(filename string) []tls.Certificate {
	if filename == "" {
		return nil
	}
	var (
		pkeyPem []byte
		certPem []byte
	)

	// read client certificate file (must include client private key and certificate)
	certFileBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		makePanic("Failed to read client certificate file: %v", err)
	}

	for {
		block, rest := pem.Decode(certFileBytes)
		if block == nil {
			break
		}
		certFileBytes = rest

		if strings.HasSuffix(block.Type, "PRIVATE KEY") {
			pkeyPem = pem.EncodeToMemory(block)
		}
		if strings.HasSuffix(block.Type, "CERTIFICATE") {
			certPem = pem.EncodeToMemory(block)
		}
	}

	cert, err := tls.X509KeyPair(certPem, pkeyPem)
	if err != nil {
		makePanic("Unable to load client cert and key pair: %v", err)
	}

	return []tls.Certificate{cert}
}

func parseURL(uri string) *url.URL {
	if !strings.Contains(uri, "://") && !strings.HasPrefix(uri, "//") {
		uri = "//" + uri
	}

	url, err := url.Parse(uri)
	if err != nil {
		makePanic("Could not parse url %q: %v", uri, err)
	}

	if url.Scheme == "" {
		url.Scheme = "http"
		if !strings.HasSuffix(url.Host, ":80") {
			url.Scheme += "s"
		}
	}
	return url
}

func headerKeyValue(h string) (string, string) {
	i := strings.Index(h, ":")
	if i == -1 {
		makePanic("Header '%s' has invalid format, missing ':'", h)
	}
	return strings.TrimRight(h[:i], " "), strings.TrimLeft(h[i:], " :")
}

func isRedirect(resp *http.Response) bool {
	return resp.StatusCode > 299 && resp.StatusCode < 400
}

// getFilenameFromHeaders tries to automatically determine the output filename,
// when saving to disk, based on the Content-Disposition header.
// If the header is not present, or it does not contain enough information to
// determine which filename to use, this function returns "".
func getFilenameFromHeaders(headers http.Header) string {
	// if the Content-Disposition header is set parse it
	if hdr := headers.Get("Content-Disposition"); hdr != "" {
		// pull the media type, and subsequent params, from
		// the body of the header field
		mt, params, err := mime.ParseMediaType(hdr)

		// if there was no error and the media type is attachment
		if err == nil && mt == "attachment" {
			if filename := params["filename"]; filename != "" {
				return filename
			}
		}
	}

	// return an empty string if we were unable to determine the filename
	return ""
}

// readResponseBody consumes the body of the response.
// readResponseBody returns an informational message about the
// disposition of the response body's contents.
func readResponseBody(req *http.Request, resp *http.Response) string {
	if isRedirect(resp) || req.Method == http.MethodHead {
		return ""
	}

	w := ioutil.Discard
	msg := "Body discarded"

	if _, err := io.Copy(w, resp.Body); err != nil {
		makePanic("Failed to read response body: %v", err)
	}

	return msg
}
