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
	command := generateAppSandboxCommand(req, podUUIDFile.Name())

	cmd := r.Command(command[0], command[1:]...)
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

	if rktUUID == "" {
		return nil, fmt.Errorf("waited 10s for pod sandbox to start, but it didn't: %v", k8sPodUid)
	}

	var readyUUID string
	for i := 0; i < 100; i++ {
		_, err := r.PodSandboxStatus(ctx, &runtimeApi.PodSandboxStatusRequest{PodSandboxId: &rktUUID})
		if err == nil {
			readyUUID = rktUUID
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if readyUUID == "" {
		return nil, fmt.Errorf("waited 10s for pod sandbox to ready, but it didn't: %q", k8sPodUid)
	}

	return &runtimeApi.RunPodSandboxResponse{PodSandboxId: &rktUUID}, nil
}

func (r *RktRuntime) StopPodSandbox(ctx context.Context, req *runtimeApi.StopPodSandboxRequest) (*runtimeApi.StopPodSandboxResponse, error) {
	if _, err := r.RunCommand("stop", req.GetPodSandboxId()); err != nil {
		return nil, err
	}
	return &runtimeApi.StopPodSandboxResponse{}, nil
}

func (r *RktRuntime) RemovePodSandbox(ctx context.Context, req *runtimeApi.RemovePodSandboxRequest) (*runtimeApi.RemovePodSandboxResponse, error) {
	if _, err := r.RunCommand("rm", req.GetPodSandboxId()); err != nil {
		return nil, err
	}
	return &runtimeApi.RemovePodSandboxResponse{}, nil
}

func (r *RktRuntime) PodSandboxStatus(ctx context.Context, req *runtimeApi.PodSandboxStatusRequest) (*runtimeApi.PodSandboxStatusResponse, error) {
	resp, err := r.RunCommand("status", req.GetPodSandboxId(), "--format=json")
	if err != nil {
		return nil, err
	}

	if len(resp) != 1 {
		return nil, fmt.Errorf("unexpected result %q", resp)
	}

	var pod Pod
	if err := json.Unmarshal([]byte(resp[0]), &pod); err != nil {
		return nil, fmt.Errorf("failed to unmarshal pod: %v", err)
	}

	status, err := toPodSandboxStatus(&pod)
	if err != nil {
		return nil, fmt.Errorf("error converting pod status: %v", err)
	}
	return &runtimeApi.PodSandboxStatusResponse{Status: status}, nil
}

func (r *RktRuntime) ListPodSandbox(ctx context.Context, req *runtimeApi.ListPodSandboxRequest) (*runtimeApi.ListPodSandboxResponse, error) {
	resp, err := r.RunCommand("list", "--format=json")
	if err != nil {
		return nil, err
	}

	if len(resp) != 1 {
		return nil, fmt.Errorf("unexpected result %q", resp)
	}

	var pods []Pod
	if err := json.Unmarshal([]byte(resp[0]), &pods); err != nil {
		return nil, fmt.Errorf("failed to unmarshal pods: %v", err)
	}

	sandboxes := make([]*runtimeApi.PodSandbox, 0, len(pods))
	for _, p := range pods {
		sandboxStatus, err := toPodSandboxStatus(&p)
		if err != nil {
			return nil, fmt.Errorf("error converting the status of pod sandbox %v: %v", p.UUID, err)
		}

		// TODO(yifan): Filter.

		sandboxes = append(sandboxes, &runtimeApi.PodSandbox{
			Id:        sandboxStatus.Id,
			Labels:    sandboxStatus.Labels,
			Metadata:  sandboxStatus.Metadata,
			State:     sandboxStatus.State,
			CreatedAt: sandboxStatus.CreatedAt,
		})
	}

	return &runtimeApi.ListPodSandboxResponse{Items: sandboxes}, nil
}
