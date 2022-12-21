/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package crictl

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	internalapi "k8s.io/cri-api/pkg/apis"
	pb "k8s.io/cri-api/pkg/apis/runtime/v1"
	"k8s.io/kubernetes/pkg/kubelet/cri/remote"
)

var runtimeVersionCommand = &cli.Command{
	Name:  "version",
	Usage: "Display runtime version information",
	Action: func(context *cli.Context) error {
		runtimeClient, err := getRuntimeService(context, 0)
		if err != nil {
			return err
		}
		err = Version(runtimeClient, string(remote.CRIVersionV1))
		if err != nil {
			return fmt.Errorf("getting the runtime version: %w", err)
		}
		return nil
	},
}

// Version sends a VersionRequest to the server, and parses the returned VersionResponse.
func Version(client internalapi.RuntimeService, version string) error {
	request := &pb.VersionRequest{Version: version}
	logrus.Debugf("VersionRequest: %v", request)
	r, err := client.Version(version)
	logrus.Debugf("VersionResponse: %v", r)
	if err != nil {
		return err
	}
	fmt.Println("Version: ", r.Version)
	fmt.Println("RuntimeName: ", r.RuntimeName)
	fmt.Println("RuntimeVersion: ", r.RuntimeVersion)
	fmt.Println("RuntimeApiVersion: ", r.RuntimeApiVersion)
	return nil
}
