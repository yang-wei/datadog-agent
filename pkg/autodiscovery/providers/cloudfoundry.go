// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-2020 Datadog, Inc.
//
// +build clusterchecks

package providers

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/DataDog/datadog-agent/pkg/autodiscovery/integration"
	"github.com/DataDog/datadog-agent/pkg/autodiscovery/providers/names"
	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/util/cloudfoundry"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/bhmj/jsonslice"
)

// CloudFoundryConfigProvider implements the Config Provider interface, it should
// be called periodically and returns templates from Cloud Foundry BBS for AutoConf.
type CloudFoundryConfigProvider struct {
	bbsCache      *cloudfoundry.BBSCache
	lastCollected time.Time
}

// NewCloudFoundryConfigProvider instantiates a new CloudFoundryConfigProvider from given config
func NewCloudFoundryConfigProvider(conf config.ConfigurationProviders) (ConfigProvider, error) {
	cfp := CloudFoundryConfigProvider{
		lastCollected: time.Now(),
	}
	var err error

	// NOTE: we can't use GetPollInterval in ConfigureGlobalBBSCache, as that causes import cycle
	cfp.bbsCache, err = cloudfoundry.GetGlobalBBSCache()
	if err != nil {
		return nil, err
	}
	return cfp, nil
}

// String returns a string representation of the CloudFoundryConfigProvider
func (cf CloudFoundryConfigProvider) String() string {
	return names.CloudFoundryBBS
}

// IsUpToDate returns true if the last collection time was later than last BBS Cache refresh time
func (cf CloudFoundryConfigProvider) IsUpToDate() (bool, error) {
	cf.bbsCache.RLock()
	defer cf.bbsCache.RUnlock()

	return cf.lastCollected.After(cf.bbsCache.LastUpdated()), nil
}

// Collect collects AD config templates from all relevant BBS API information
func (cf CloudFoundryConfigProvider) Collect() ([]integration.Config, error) {
	cf.bbsCache.RLock()
	defer cf.bbsCache.RUnlock()

	cf.lastCollected = time.Now()
	desiredLRPs := cf.bbsCache.GetDesiredLRPs()
	allConfigs := []integration.Config{}
	for _, desiredLRP := range desiredLRPs {
		newConfigs := cf.getConfigsFromDesiredLRP(desiredLRP)
		log.Debugf("Successfully got %d configs for app %s", len(newConfigs), desiredLRP.AppGUID)
		allConfigs = append(allConfigs, newConfigs...)
	}
	return allConfigs, nil
}

func (cf CloudFoundryConfigProvider) getConfigsFromDesiredLRP(desiredLRP cloudfoundry.DesiredLRP) []integration.Config {
	allConfigs := []integration.Config{}

	for adName, adVal := range desiredLRP.EnvAD {
		// initially, let's assume a non-container service; we'll change to container service in
		// `expandPerContainerChecks` if necessary
		id := cloudfoundry.NewADNonContainerIdentifier(desiredLRP, adName)
		// we need to convert adVal to map[string]string to pass it to extractTemplatesFromMap
		convertedADVal := map[string]string{}
		for k, v := range adVal {
			convertedADVal[k] = string(v)
		}
		parsedConfigs, errs := extractTemplatesFromMap(id.String(), convertedADVal, "")
		for _, err := range errs {
			log.Errorf("Cannot parse endpoint template for service %s of app %s: %s, skipping",
				adName, desiredLRP.AppGUID, err)
		}

		vcVal, vcOk := desiredLRP.EnvVcapServices[adName]
		variables, varsOk := adVal["variables"]
		success := false
		if vcOk {
			// if service is found in VCAP_SERVICES (non-container service), we will run a single check per App
			err := cf.renderExtractedConfigs(parsedConfigs, variables, vcVal)
			cf.assignNodeNameToNonContainerChecks(parsedConfigs, desiredLRP)
			if err != nil {
				log.Errorf("Failed to render config for service %s of app %s: %s", adName, desiredLRP.AppGUID, err)
			} else {
				success = true
			}
		} else if varsOk {
			log.Errorf("Service %s for app %s has variables configured, but is not present in VCAP_SERVICES", adName, desiredLRP.AppGUID)
		} else {
			// if a service is not in VCAP_SERVICES and has no "variables" configured, we want to run a check per container
			parsedConfigs = cf.expandPerContainerChecks(parsedConfigs, desiredLRP, adName)
			success = true
		}
		if success {
			// mark all checks as cluster checks
			for i := range parsedConfigs {
				parsedConfigs[i].ClusterCheck = true
			}
			allConfigs = append(allConfigs, parsedConfigs...)
		}
	}

	return allConfigs
}

func (cf CloudFoundryConfigProvider) assignNodeNameToNonContainerChecks(configs []integration.Config, desiredLRP cloudfoundry.DesiredLRP) {
	aLRPs := cf.bbsCache.GetActualLRPsFor(desiredLRP.AppGUID)

	if len(aLRPs) > 0 {
		aLRP := aLRPs[0]
		log.Debugf("All non-container checks for app %s will run on Cell %s", desiredLRP.AppGUID, aLRP.CellID)
		for i := range configs {
			configs[i].NodeName = aLRP.CellID
		}
	} else {
		log.Infof("No container running for app %s, checks for its non-container services will run on arbitrary node", desiredLRP.AppGUID)
	}
}

func (cf CloudFoundryConfigProvider) expandPerContainerChecks(
	configs []integration.Config, desiredLRP cloudfoundry.DesiredLRP, svcName string) []integration.Config {
	res := []integration.Config{}
	for _, cfg := range configs {
		for _, aLRP := range cf.bbsCache.GetActualLRPsFor(desiredLRP.AppGUID) {
			// we append container index to AD Identifier distinguish configs for different containers
			newCfg := integration.Config{
				ADIdentifiers: []string{cloudfoundry.NewADContainerIdentifier(desiredLRP, svcName, aLRP).String()},
				ClusterCheck:  cfg.ClusterCheck,
				Entity:        cfg.Entity, // TODO: should we modify this as well as ADIdentifiers?
				InitConfig:    cfg.InitConfig,
				Instances:     cfg.Instances,
				LogsConfig:    cfg.LogsConfig,
				MetricConfig:  cfg.MetricConfig,
				Name:          cfg.Name,
				// make sure this check runs on the node that's running this container
				NodeName:      aLRP.CellID,
				Provider:      cfg.Provider,
				Source:        cfg.Source,
			}
			res = append(res, newCfg)
		}
	}

	return res
}

func (cf CloudFoundryConfigProvider) renderExtractedConfigs(configs []integration.Config, variables json.RawMessage, vcap []byte) error {
	// TODO: validate variable names are sane?
	var vars map[string]string
	err := json.Unmarshal(variables, &vars)
	if err != nil {
		return err
	}
	replaceList := []string{}
	for varName, varPath := range vars {
		value, err := jsonslice.Get(vcap, varPath)
		if err != nil {
			return err
		}
		valStr := string(value)
		if len(valStr) > 0 {
			// remove all \", [] and {} from results; users can easily add these themselves, but they wouldn't be able
			// to remove them easily
			switch valStr[0] {
			case '"':
				valStr = strings.Trim(string(value), "\"")
			case '[':
				valStr = strings.Trim(string(value), "[]")
			case '{':
				valStr = strings.Trim(string(value), "{}")
			}
		}
		replaceList = append(replaceList, fmt.Sprintf("%%%%%s%%%%", varName), valStr)
	}

	replacer := strings.NewReplacer(replaceList...)

	for _, cfg := range configs {
		for i, inst := range cfg.Instances {
			newInst := replacer.Replace(string(inst))
			cfg.Instances[i] = integration.Data(newInst)
		}
	}

	return nil
}

func init() {
	RegisterProvider(names.CloudFoundryBBS, NewCloudFoundryConfigProvider)
}
