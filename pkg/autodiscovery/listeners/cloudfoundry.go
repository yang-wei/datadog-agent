// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2017-2020 Datadog, Inc.

// +build clusterchecks

package listeners

import (
	"fmt"
	"sync"
	"time"

	"github.com/DataDog/datadog-agent/pkg/autodiscovery/integration"
	"github.com/DataDog/datadog-agent/pkg/util/cloudfoundry"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

const (
	CF_SERVICE_CONTAINER_IP = "container-ip"
)

type CloudFoundryListener struct {
	newService chan<- Service
	delService chan<- Service
	services   map[string]Service // maps ADIdentifiers to services
	stop       chan bool
	t          *time.Ticker
	m          sync.RWMutex
	bbsCache   *cloudfoundry.BBSCache
}

type CloudFoundryService struct {
	adIdentifier   cloudfoundry.ADIdentifier
	checkNames     []string
	containerIPs   map[string]string
	containerPorts []ContainerPort
	creationTime   integration.CreationTime
}

// Make sure CloudFoundryService implements the Service interface
var _ Service = &CloudFoundryService{}

func init() {
	Register("cloudfoundry-bbs", NewCloudFoundryListener)
}

// NewCloudFoundryListener creates a CloudFoundryListener
func NewCloudFoundryListener() (ServiceListener, error) {
	bbsCache, _ := cloudfoundry.GetGlobalBBSCache()
	return &CloudFoundryListener{
		services: map[string]Service{},
		stop:     make(chan bool),
		t:        time.NewTicker(10 * time.Second),
		bbsCache: bbsCache,
	}, nil
}

// Listen periodically refreshes services from global BBS API cache
func (l *CloudFoundryListener) Listen(newSvc chan<- Service, delSvc chan<- Service) {
	// setup the I/O channels
	l.newService = newSvc
	l.delService = delSvc

	go func() {
		l.refreshServices(true)
		for {
			select {
			case <-l.stop:
				return
			case <-l.t.C:
				l.refreshServices(false)
			}
		}
	}()
}

func (l *CloudFoundryListener) refreshServices(firstRun bool) {
	if l.bbsCache == nil {
		var err error
		l.bbsCache, err = cloudfoundry.GetGlobalBBSCache()
		if err != nil {
			log.Warnf("Can't refresh services list: %s", err.Error())
			return
		}
	}
	l.bbsCache.RLock()
	defer l.bbsCache.RUnlock()

	// if not found and running, add it
	// at the end, compare what we saw and what is cached and kill what's not there anymore
	notSeen := make(map[string]interface{})
	for i := range l.services {
		notSeen[i] = nil
	}

	adIdentifiers := l.getAllADIdentifiers()
	for _, id := range adIdentifiers {
		strId := id.String()
		if _, found := l.services[strId]; found {
			// delete is no-op when we try to delete a key that doesn't exist
			// NOTE: this will remove old versions of services on redeploys because ADIdentifier contains ProcessGUID,
			//       which changes by redeploying
			delete(notSeen, strId)
			continue
		}
		// TODO: handle container state?
		svc := l.createService(id, firstRun)
		l.newService <- svc
	}

	for adId := range notSeen {
		l.m.RLock()
		l.delService <- l.services[adId]
		l.m.RUnlock()
		l.m.Lock()
		delete(l.services, adId)
		l.m.Unlock()
	}
}

func (l *CloudFoundryListener) createService(adId cloudfoundry.ADIdentifier, firstRun bool) *CloudFoundryService {
	l.m.Lock()
	defer l.m.Unlock()
	var crTime integration.CreationTime
	if firstRun {
		crTime = integration.Before
	} else {
		crTime = integration.After
	}

	var svc *CloudFoundryService
	aLRP := adId.GetActualLRP()
	if aLRP == nil {
		// non-container service
		svc = &CloudFoundryService{
			adIdentifier:   adId,
			checkNames:     []string{},          // TODO
			containerIPs:   map[string]string{}, // TODO
			containerPorts: []ContainerPort{},   // TODO
			creationTime:   crTime,
		}
	} else {
		// container service => we need one service per container instance
		ips := map[string]string{CF_SERVICE_CONTAINER_IP: aLRP.ContainerIP}
		ports := []ContainerPort{}
		for _, p := range aLRP.Ports {
			ports = append(ports, ContainerPort{
				// TODO: because of how configresolver.getPort works, we can't use e.g. port_8080, so we use port_p8080
				// can we change that logic?
				Name: fmt.Sprintf("p%d", p),
				Port: int(p),
			})
		}
		svc = &CloudFoundryService{
			adIdentifier:   adId,
			checkNames:     []string{}, // TODO
			containerIPs:   ips,
			containerPorts: ports,
			creationTime:   crTime,
		}
	}
	l.services[adId.String()] = svc
	return svc
}

func (l *CloudFoundryListener) getAllADIdentifiers() []cloudfoundry.ADIdentifier {
	ret := []cloudfoundry.ADIdentifier{}
	for _, dLRP := range l.bbsCache.GetDesiredLRPs() {
		for adName, _ := range dLRP.EnvAD {
			if _, ok := dLRP.EnvVcapServices[adName]; ok {
				// if it's in VCAP_SERVICES, it's a non-container service and we want one instance per App
				ret = append(ret, cloudfoundry.NewADNonContainerIdentifier(dLRP, adName))
			} else {
				// if it's not in VCAP_SERVICES, it's a container service and we want one instance per container
				for _, aLRP := range l.bbsCache.GetActualLRPsFor(dLRP.AppGUID) {
					ret = append(ret, cloudfoundry.NewADContainerIdentifier(dLRP, adName, aLRP))
				}
			}
		}
	}
	return ret
}

// Stop queues a shutdown of CloudFoundryListener
func (l *CloudFoundryListener) Stop() {
	l.stop <- true
}

// GetEntity returns the unique entity name linked to that service
func (s *CloudFoundryService) GetEntity() string {
	return s.adIdentifier.String()
}

// GetTaggerEntity returns the unique entity name linked to that service
func (s *CloudFoundryService) GetTaggerEntity() string {
	return s.adIdentifier.String()
}

// GetADIdentifiers returns a set of AD identifiers for a container.
func (s *CloudFoundryService) GetADIdentifiers() ([]string, error) {
	return []string{s.adIdentifier.String()}, nil
}

// GetHosts returns the container's hosts
func (s *CloudFoundryService) GetHosts() (map[string]string, error) {
	return s.containerIPs, nil
}

// GetPorts returns the container's ports
func (s *CloudFoundryService) GetPorts() ([]ContainerPort, error) {
	return s.containerPorts, nil
}

// GetTags returns the list of container tags - currently always empty
func (s *CloudFoundryService) GetTags() ([]string, error) {
	return []string{}, nil
}

// GetPid returns nil and an error because pids are currently not supported in CF
func (s *CloudFoundryService) GetPid() (int, error) {
	return -1, ErrNotSupported
}

// GetHostname returns nil and an error because hostnames are not supported in CF
func (s *CloudFoundryService) GetHostname() (string, error) {
	return "", ErrNotSupported
}

// GetCreationTime returns the creation time of the container
func (s *CloudFoundryService) GetCreationTime() integration.CreationTime {
	return s.creationTime
}

// IsReady always returns true on CF
func (s *CloudFoundryService) IsReady() bool {
	return true
}

// GetCheckNames always returns empty slice on CF
// TODO: do we need to implement this?
func (s *CloudFoundryService) GetCheckNames() []string {
	return s.checkNames
}
