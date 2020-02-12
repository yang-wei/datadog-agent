// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2017-2020 Datadog, Inc.

// +build kubeapiserver

package custommetrics

import (
	"context"
	"github.com/DataDog/datadog-agent/pkg/clusteragent"
)

type RunServerFunc func(ctx context.Context) error

func GetRunServerFunc(platform clusteragent.ClusterAgentPlatform) (RunServerFunc, error) {
	switch platform {
	case clusteragent.PlatformCloudFoundry:
		return runServerCloudFoundry, nil
	case clusteragent.PlatformKubernetes:
		return runServerKubernetes, nil
	}

	return nil, clusteragent.UnknownPlatformErr(platform)
}
