package filters

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/golang/glog"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
)

func WithAuthentication(handler http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// send out a request to mds
		if instanceId, err := authRemoteAdd(req.RemoteAddr); err == nil {
			glog.Infof("Ydev: authenticated as %v", instanceId)
			req = req.WithContext(genericapirequest.WithLatteCreator(
				req.Context(), instanceId))
		}

		handler.ServeHTTP(w, req)
	})
}

var (
	mds_client *http.Client
)

func init() {
	tr := &httpTransport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
	}

	mds_client = &http.Client{Transport: tr}
}

func authRemoteAddr(addr string) (string, error) {
	resp, err := mds_client.Get(fmt.Sprintf("http://mds:19851/authenticate/%s", addr))

	if err != nil {
		glog.Infof("Ydev: failed to authenticate remote address %v", err)
		return "", err
	}

	if data, err := ioutil.ReadAll(resp.Body); err != nil {
		return nil, err
	} else {
		return string(data), nil
	}
}
