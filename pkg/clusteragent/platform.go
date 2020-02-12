// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-2020 Datadog, Inc.

package clusteragent

import (
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/config"
)

type ClusterAgentPlatform string

const (
	PlatformCloudFoundry ClusterAgentPlatform = "cloudfoundry"
	PlatformKubernetes   ClusterAgentPlatform = "kubernetes"
)

func GetClusterAgentPlatform() ClusterAgentPlatform {
	if config.Datadog.GetString("cloudfoundry_bbs_api_url") != "" {
		return PlatformCloudFoundry
	}

	return PlatformKubernetes
}

func UnknownPlatformErr(platform ClusterAgentPlatform) error {
	return fmt.Errorf("Unknown cluster agent platform %s", platform)
}
