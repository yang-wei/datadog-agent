// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-2020 Datadog, Inc.

// Package agent implements the api endpoints for the `/agent` prefix.
// This group of endpoints is meant to provide high-level functionalities
// at the agent level.
package agent

import (
	"encoding/json"
	"fmt"
	"github.com/DataDog/datadog-agent/cmd/agent/common/jsonpatch"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"
	"net/http"
	"sort"

	"github.com/gorilla/mux"
	yaml "gopkg.in/yaml.v2"

	"github.com/DataDog/datadog-agent/cmd/agent/api/response"
	"github.com/DataDog/datadog-agent/cmd/agent/common"
	"github.com/DataDog/datadog-agent/cmd/agent/common/signals"
	v1 "github.com/DataDog/datadog-agent/cmd/cluster-agent/api/v1"
	"github.com/DataDog/datadog-agent/pkg/autodiscovery"
	"github.com/DataDog/datadog-agent/pkg/autodiscovery/integration"
	"github.com/DataDog/datadog-agent/pkg/clusteragent"
	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/flare"
	"github.com/DataDog/datadog-agent/pkg/status"
	"github.com/DataDog/datadog-agent/pkg/util"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/version"
)

// SetupHandlers adds the specific handlers for cluster agent endpoints
func SetupHandlers(r *mux.Router, sc clusteragent.ServerContext) {
	r.HandleFunc("/version", getVersion).Methods("GET")
	r.HandleFunc("/hostname", getHostname).Methods("GET")
	r.HandleFunc("/flare", makeFlare).Methods("POST")
	r.HandleFunc("/stop", stopAgent).Methods("POST")
	r.HandleFunc("/status", getStatus).Methods("GET")
	r.HandleFunc("/config-check", getConfigCheck).Methods("GET")
	r.HandleFunc("/config", getRuntimeConfig).Methods("GET")
	r.HandleFunc("/application-mutating-webhook", getApplicationMutatingWebhook).Methods("POST")

	// Install versioned apis
	v1.Install(r.PathPrefix("/api/v1").Subrouter(), sc)
}

func getStatus(w http.ResponseWriter, r *http.Request) {
	log.Info("Got a request for the status. Making status.")
	s, err := status.GetDCAStatus()
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		log.Errorf("Error getting status. Error: %v, Status: %v", err, s)
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), 500)
		return
	}
	jsonStats, err := json.Marshal(s)
	if err != nil {
		log.Errorf("Error marshalling status. Error: %v, Status: %v", err, s)
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), 500)
		return
	}
	w.Write(jsonStats)
}

func stopAgent(w http.ResponseWriter, r *http.Request) {
	signals.Stopper <- true
	w.Header().Set("Content-Type", "application/json")
	j, _ := json.Marshal("")
	w.Write(j)
}

func getVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	av, err := version.Agent()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), 500)
		return
	}
	j, err := json.Marshal(av)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), 500)
		return
	}
	w.Write(j)
}

func getHostname(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	hname, err := util.GetHostname()
	if err != nil {
		log.Warnf("Error getting hostname: %s", err)
		hname = ""
	}
	j, err := json.Marshal(hname)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), 500)
		return
	}
	w.Write(j)
}

func makeFlare(w http.ResponseWriter, r *http.Request) {
	log.Infof("Making a flare")
	w.Header().Set("Content-Type", "application/json")
	logFile := config.Datadog.GetString("log_file")
	if logFile == "" {
		logFile = common.DefaultDCALogFile
	}
	filePath, err := flare.CreateDCAArchive(false, common.GetDistPath(), logFile)
	if err != nil || filePath == "" {
		if err != nil {
			log.Errorf("The flare failed to be created: %s", err)
		} else {
			log.Warnf("The flare failed to be created")
		}
		http.Error(w, err.Error(), 500)
	}
	w.Write([]byte(filePath))
}

func getConfigCheck(w http.ResponseWriter, r *http.Request) {
	var response response.ConfigCheckResponse

	if common.AC == nil {
		log.Errorf("Trying to use /config-check before the agent has been initialized.")
		body, _ := json.Marshal(map[string]string{"error": "agent not initialized"})
		http.Error(w, string(body), 503)
		return
	}

	configs := common.AC.GetLoadedConfigs()
	configSlice := make([]integration.Config, 0)
	for _, config := range configs {
		configSlice = append(configSlice, config)
	}
	sort.Slice(configSlice, func(i, j int) bool {
		return configSlice[i].Name < configSlice[j].Name
	})
	response.Configs = configSlice
	response.ResolveWarnings = autodiscovery.GetResolveWarnings()
	response.ConfigErrors = autodiscovery.GetConfigErrors()
	response.Unresolved = common.AC.GetUnresolvedTemplates()

	jsonConfig, err := json.Marshal(response)
	if err != nil {
		log.Errorf("Unable to marshal config check response: %s", err)
		body, _ := json.Marshal(map[string]string{"error": err.Error()})
		http.Error(w, string(body), 500)
		return
	}

	w.Write(jsonConfig)
}

func getRuntimeConfig(w http.ResponseWriter, r *http.Request) {
	runtimeConfig, err := yaml.Marshal(config.Datadog.AllSettings())
	if err != nil {
		log.Errorf("Unable to marshal runtime config response: %s", err)
		body, _ := json.Marshal(map[string]string{"error": err.Error()})
		http.Error(w, string(body), 500)
		return
	}
	w.Write(runtimeConfig)
}

func getApplicationMutatingWebhook(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)

	// The AdmissionReview that was sent to the webhook
	requestedAdmissionReview := admissionv1beta1.AdmissionReview{}
	err := decoder.Decode(&requestedAdmissionReview)
	if err != nil {
		log.Errorf("Unable to parse request: %s", err)
		body, _ := json.Marshal(map[string]string{"error": err.Error()})
		http.Error(w, string(body), 500)
		return
	}

	// The AdmissionReview that will be returned
	responseAdmissionReview := admissionv1beta1.AdmissionReview{}

	// pass to admitFunc
	responseAdmissionReview.Response = mutatePods(requestedAdmissionReview)

	// Return the same UID
	responseAdmissionReview.Response.UID = requestedAdmissionReview.Request.UID

	respBytes, err := json.Marshal(responseAdmissionReview)
	if err != nil {
		klog.Error(err)
	}
	if _, err := w.Write(respBytes); err != nil {
		klog.Error(err)
	}
}


// toAdmissionResponse is a helper function to create an AdmissionResponse
// with an embedded error
func toAdmissionResponse(err error) *admissionv1beta1.AdmissionResponse {
	return &admissionv1beta1.AdmissionResponse{
		Result: &metav1.Status{
			Message: err.Error(),
		},
	}
}

func mutatePods(ar admissionv1beta1.AdmissionReview) *admissionv1beta1.AdmissionResponse {
	klog.Info("mutating pods")
	podResource := metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	if ar.Request.Resource != podResource {
		klog.Errorf("expect resource to be %s, got %v", podResource, ar.Request.Resource)

		return &admissionv1beta1.AdmissionResponse{Allowed: true}
	}

	pod := corev1.Pod{}
	if err := json.Unmarshal(ar.Request.Object.Raw, &pod); err != nil {
		klog.Error(err)
		return toAdmissionResponse(err)
	}

	patch, _ := mutatePod(pod)
	klog.Infof("jsonPath: %v", patch)

	reviewResponse := mutateResponse(patch)

	klog.Infof("reviewResponse: %v", reviewResponse)

	return reviewResponse
}

func mutateResponse(patch jsonpatch.Patch) *admissionv1beta1.AdmissionResponse {
	bs, _ := json.Marshal(patch)
	patchType := admissionv1beta1.PatchTypeJSONPatch
	return &admissionv1beta1.AdmissionResponse{
		Allowed:   true,
		Patch:     bs,
		PatchType: &patchType,
	}
}

// NewEnvMutator creates a new mutator which adds environment
// variables to pods
func getEnvMutator() []corev1.EnvVar {
	return []corev1.EnvVar{
		{
			Name: "DD_AGENT_HOST",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "status.hostIP",
				},
			},
		},
		{
			Name: "DEV_TEST_VERSION",
			Value: "dev-1",
		},
	}
}

func mutatePod(pod corev1.Pod) (jsonpatch.Patch, error) {
	var envVariables = getEnvMutator()

	containerLists := []struct {
		field      string
		containers []corev1.Container
	}{
		{"initContainers", pod.Spec.InitContainers},
		{"containers", pod.Spec.Containers},
	}

	var patch jsonpatch.Patch

	for _, s := range containerLists {
		field, containers := s.field, s.containers
		for i, container := range containers {
			if len(container.Env) == 0 {
				patch = append(patch, jsonpatch.Add(
					fmt.Sprint("/spec/", field, "/", i, "/env"),
					[]interface{}{},
				))
			}

			remainingEnv := make([]corev1.EnvVar, len(container.Env))
			copy(remainingEnv, container.Env)

		injectedEnvLoop:
			for envPos, def := range envVariables {
				for pos, v := range remainingEnv {
					if v.Name == def.Name {
						if currPos, destPos := envPos+pos, envPos; currPos != destPos {
							// This should ideally be a `move` operation but due to a bug in the json-patch's
							// implementation of `move` operation, we explicitly use `remove` followed by `add`.
							// see, https://github.com/evanphx/json-patch/pull/73
							// This is resolved in json-patch `v4.2.0`, which is pulled by Kubernetes `1.14.3` clusters.
							// https://github.com/kubernetes/kubernetes/blob/v1.14.3/Godeps/Godeps.json#L1707-L1709
							// TODO: Use a `move` operation, once all clusters are on `1.14.3+`
							patch = append(patch,
								jsonpatch.Remove(
									fmt.Sprint("/spec/", field, "/", i, "/env/", currPos),
								),
								jsonpatch.Add(
									fmt.Sprint("/spec/", field, "/", i, "/env/", destPos),
									v,
								))
						}
						remainingEnv = append(remainingEnv[:pos], remainingEnv[pos+1:]...)
						continue injectedEnvLoop
					}
				}

				patch = append(patch, jsonpatch.Add(
					fmt.Sprint("/spec/", field, "/", i, "/env/", envPos),
					def,
				))
			}
		}
	}
	return patch, nil
}
