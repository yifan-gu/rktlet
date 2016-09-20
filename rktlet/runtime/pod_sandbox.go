/*
Copyright 2016 The Kubernetes Authors.

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

package runtime

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	context "golang.org/x/net/context"

	"github.com/golang/glog"

	runtimeApi "k8s.io/kubernetes/pkg/kubelet/api/v1alpha1/runtime"
)

func formatPod(metaData *runtimeApi.PodSandboxMetadata) string {
	return fmt.Sprintf("%s_%s(%s)", metaData.Name, metaData.Namespace, metaData.Uid)
}

func (r *RktRuntime) RunPodSandbox(ctx context.Context, req *runtimeApi.RunPodSandboxRequest) (*runtimeApi.RunPodSandboxResponse, error) {
	metaData := req.GetConfig().GetMetadata()
	k8sPodUid := metaData.GetUid()
	podUUIDFile, err := ioutil.TempFile("", "rktlet_"+k8sPodUid)
	defer os.Remove(podUUIDFile.Name())
	if err != nil {
		return nil, fmt.Errorf("could not create temporary file for rkt UUID: %v", err)
	}

	// Let the init process to run the pod sandbox.
	cmd := r.Command("app", "sandbox", "--uuid-file-save="+podUUIDFile.Name())
	id, err := r.Init.StartProcess(cmd[0], cmd[1:]...)
	if err != nil {
		glog.Errorf("failed to run pod %q: %v", formatPod(metaData), err)
		return nil, err

	}

	glog.V(4).Infof("pod sandbox is running as service %q", id)

	var rktUUID string
	// TODO, inotify watch for the uuid file would be slightly more efficient
	// We could also create a pair of pipes for this
	for i := 0; i < 100; i++ {
		data, err := ioutil.ReadAll(podUUIDFile)
		if err != nil {
			return nil, fmt.Errorf("error reading rkt pod UUID file: %v", err)
		}
		if len(data) != 0 {
			rktUUID = string(data)
			break
		}

		time.Sleep(100 * time.Millisecond)
	}

	for i := 0; i < 100; i++ {
		// Read pod manifest to make sure pod is running.
		_, err := r.PodSandboxStatus(ctx, &runtimeApi.PodSandboxStatusRequest{PodSandboxId: &rktUUID})
		if err == nil {
			rktUUID = ""
			break
		}
		time.Sleep(100 * time.Microsecond)
	}

	if rktUUID == "" {
		return nil, fmt.Errorf("waited 10s for pod sandbox to start, but it didn't: %v", k8sPodUid)
	}

	return &runtimeApi.RunPodSandboxResponse{
		PodSandboxId: &rktUUID,
	}, nil
}

func (r *RktRuntime) StopPodSandbox(ctx context.Context, req *runtimeApi.StopPodSandboxRequest) (*runtimeApi.StopPodSandboxResponse, error) {
	respLines, err := r.RunCommand("stop", req.GetPodSandboxId())
	if err != nil {
		// TODO, structured output will be so much nicer!
		for _, line := range respLines {
			if strings.HasSuffix(line, "is not running") {
				return &runtimeApi.StopPodSandboxResponse{}, nil
			}
		}
		return nil, err
	}
	return &runtimeApi.StopPodSandboxResponse{}, err
}

func (r *RktRuntime) RemovePodSandbox(ctx context.Context, req *runtimeApi.RemovePodSandboxRequest) (*runtimeApi.RemovePodSandboxResponse, error) {
	if _, err := r.RunCommand("rm", req.GetPodSandboxId()); err != nil {
		return nil, err
	}
	return &runtimeApi.RemovePodSandboxResponse{}, nil
}

func (r *RktRuntime) PodSandboxStatus(ctx context.Context, req *runtimeApi.PodSandboxStatusRequest) (*runtimeApi.PodSandboxStatusResponse, error) {
	resp, err := r.RunCommand("status", req.GetPodSandboxId())
	if err != nil {
		return nil, err
	}

	rktStatus := parseRktStatus(resp)
	apiStatus := runtimeApi.PodSandBoxState_NOTREADY
	var ip string
	if rktStatus.state == "running" {
		apiStatus = runtimeApi.PodSandBoxState_READY
		ip = parseRktNetworkIp(rktStatus.networks)
	}

	createdUnix := rktStatus.created.Unix()
	return &runtimeApi.PodSandboxStatusResponse{
		Status: &runtimeApi.PodSandboxStatus{
			Id:          req.PodSandboxId,
			Metadata:    nil, // TODO
			State:       &apiStatus,
			CreatedAt:   &createdUnix,
			Network:     &runtimeApi.PodSandboxNetworkStatus{Ip: &ip},
			Linux:       nil, // TODO
			Labels:      nil, // TODO
			Annotations: nil, // TODO
		},
	}, nil
}

type rktStatusResponse struct {
	state    string
	created  time.Time
	networks string
}

func parseRktStatus(status []string) rktStatusResponse {
	resp := rktStatusResponse{}

	for _, line := range status {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			glog.Warningf("malformed rkt status response: expected an '=', got: %v", line)
			continue
		}

		switch parts[0] {
		case "state":
			resp.state = parts[1]
		case "created":
			time, err := time.Parse("2006-01-02 15:04:05.999 -0700 MST", parts[1])
			if err != nil {
				glog.Warningf("error parsing rkt started time: %v", err)
			}
			resp.created = time
		case "networks":
			resp.networks = parts[1]
		}
	}

	return resp
}

// parseRktNetworkIp parses the `rkt status` formatted network into an ip.
// The ip of a network named rkt.kubernetes.io will be preferred, followed by
// default, followed by the first one
// The input might look something like 'default:ip4=172.16.28.27,foo:ip4=x.y.z.a'
func parseRktNetworkIp(networks string) string {
	podNetworks := strings.Split(networks, ",")

	foundIp := "" // best ip we've found yet by the criterion above
	for _, network := range podNetworks {
		networkParts := strings.Split(network, ":")
		if len(networkParts) < 2 {
			glog.Warningf("malformed rkt network part; should have at least one ':': %v", network)
			continue
		}
		networkName := networkParts[0]
		for _, networkIp := range networkParts[1:] {
			networkIpParts := strings.Split(networkIp, "=")
			if len(networkIpParts) != 2 {
				glog.Warningf("malformed rkt networkIp part; should have one '=': %v", networkIp)
				continue
			}
			if networkIpParts[0] != "ip4" {
				// k8s only supports ipv4
				continue
			}

			if networkName == "rkt.kubernetes.io" {
				// Always prefer this network if available. We're done if we find it
				return networkIpParts[1]
			}
			if networkName == "default" {
				// even if we already have a previous ip, prefer default over it. If it
				// was rkt.k8s we already returned, so it must have been an arbitrary
				// one
				foundIp = networkIpParts[1]
			}

			if foundIp == "" {
				// If nothing else has matched, we can use this one, but keep going to
				// see if we find 'default' or 'rkt.k8s.io'
				foundIp = networkIpParts[1]
			}
		}
	}
	return foundIp
}

func (r *RktRuntime) ListPodSandbox(ctx context.Context, req *runtimeApi.ListPodSandboxRequest) (*runtimeApi.ListPodSandboxResponse, error) {
	resp, err := r.RunCommand("list", "--full=true", "--no-legend=true", "--format=json")
	if err != nil {
		return nil, err
	}

	// TODO, we should not call status for all of these, just get enough info from list in the first place

	if len(resp) != 1 {
		return nil, fmt.Errorf("unexpected result %q", resp)
	}

	var pods []Pod
	if err := json.Unmarshal([]byte(resp[0]), &pods); err != nil {
		return nil, fmt.Errorf("failed to unmarshal pods: %v", err)
	}

	sandboxes := make([]*runtimeApi.PodSandbox, 0, len(pods))

	for _, p := range pods {
		sandboxStatus, err := r.PodSandboxStatus(ctx, &runtimeApi.PodSandboxStatusRequest{
			PodSandboxId: &p.UUID,
		})
		if err != nil {
			return nil, fmt.Errorf("error getting status of pod sandbox %v: %v", p.UUID, err)
		}

		// TODO(yifan): Filter.

		sandboxes = append(sandboxes, &runtimeApi.PodSandbox{
			Id:        sandboxStatus.Status.Id,
			Labels:    sandboxStatus.Status.Labels,
			Metadata:  sandboxStatus.Status.Metadata,
			State:     sandboxStatus.Status.State,
			CreatedAt: sandboxStatus.Status.CreatedAt,
		})
	}

	return &runtimeApi.ListPodSandboxResponse{
		Items: sandboxes,
	}, nil
}
