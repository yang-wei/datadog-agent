// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-2020 Datadog, Inc.

// +build kubeapiserver

package app

import "github.com/DataDog/datadog-agent/pkg/clusteragent"

type StartControllersFunc func() error

func GetStartControllersFunc(platform clusteragent.ClusterAgentPlatform) (StartControllersFunc, error) {
	switch platform {
	case clusteragent.PlatformCloudFoundry:
		return startControllersCloudFoundry, nil
	case clusteragent.PlatformKubernetes:
		return startControllersKubernetes, nil
	}

	return nil, clusteragent.UnknownPlatformErr(platform)
}

