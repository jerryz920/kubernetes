package filters

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/golang/glog"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
)

func WithLatteAuthentication(handler http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// send out a request to mds

		if user, ok := genericapirequest.UserFrom(req.Context()); ok {
			name := user.GetName()
			// only auth for service account and non-system accounts
			auth := true

			if strings.HasPrefix(name, "system:serviceaccount:kube-system") {
				auth = false
			} else if strings.HasPrefix(name, "system:") && !strings.HasPrefix(name, "system:serviceaccount") {
				auth = false
			} else if name == "kubernetes-admin" {
				auth = false
			}

			if auth {
				glog.Infof("Ydev who to authenticate: %v", name)
				if instanceIds, err := authRemoteAddr(req.RemoteAddr); err == nil && strings.Trim(instanceIds, " \n") != "" {
					pids := strings.Split(instanceIds, "\n")
					glog.Infof("Ydev: authenticated as %v %v", pids[0], pids[1])
					req = req.WithContext(genericapirequest.WithLatteCreator(
						req.Context(), pids[0]))
				}
			}
		}

		handler.ServeHTTP(w, req)
	})
}

var (
	mds_client *http.Client
)

func init() {
	tr := &http.Transport{
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
		return "", err
	} else {
		return string(data), nil
	}
}
