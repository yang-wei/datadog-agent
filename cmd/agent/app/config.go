// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-2020 Datadog, Inc.

package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"

	"github.com/DataDog/datadog-agent/cmd/agent/common"
	"github.com/DataDog/datadog-agent/pkg/api/util"
	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

func init() {
	AgentCmd.AddCommand(configCommand)
	configCommand.AddCommand(listRuntimeCommand)
	configCommand.AddCommand(setCommand)
}

var (
	configCommand = &cobra.Command{
		Use:   "config",
		Short: "Print the runtime configuration of a running agent",
		Long:  ``,
		RunE:  showRuntimeConfiguration,
	}
	listRuntimeCommand = &cobra.Command{
		Use:   "list-runtime",
		Short: "List settings that can be changed at runtime",
		Long:  ``,
		RunE:  listRuntimeConfigurableValue,
	}
	setCommand = &cobra.Command{
		Use:   "set [setting] [value]",
		Short: "Set, for the current runtime, the value of a given configuration setting",
		Long:  ``,
		RunE:  setConfigValue,
	}
)

func showRuntimeConfiguration(cmd *cobra.Command, args []string) error {
	if flagNoColor {
		color.NoColor = true
	}

	err := common.SetupConfigWithoutSecrets(confFilePath, "")
	if err != nil {
		return fmt.Errorf("unable to set up global agent configuration: %v", err)
	}

	err = config.SetupLogger(loggerName, config.GetEnv("DD_LOG_LEVEL", "off"), "", "", false, true, false)
	if err != nil {
		fmt.Printf("Cannot setup logger, exiting: %v\n", err)
		return err
	}

	err = util.SetAuthToken()
	if err != nil {
		return err
	}

	runtimeConfig, err := requestConfig()
	if err != nil {
		return err
	}

	fmt.Println(runtimeConfig)
	return nil
}

func requestConfig() (string, error) {
	c := util.GetClient(false)
	ipcAddress, err := config.GetIPCAddress()
	if err != nil {
		return "", err
	}
	apiConfigURL := fmt.Sprintf("https://%v:%v/agent/config", ipcAddress, config.Datadog.GetInt("cmd_port"))

	r, err := util.DoGet(c, apiConfigURL)
	if err != nil {
		var errMap = make(map[string]string)
		json.Unmarshal(r, &errMap)
		// If the error has been marshalled into a json object, check it and return it properly
		if e, found := errMap["error"]; found {
			return "", fmt.Errorf(e)
		}

		return "", fmt.Errorf("Could not reach agent: %v \nMake sure the agent is running before requesting the runtime configuration and contact support if you continue having issues", err)
	}

	return string(r), nil
}

func listRuntimeConfigurableValue(cmd *cobra.Command, args []string) error {
	err := util.SetAuthToken()
	if err != nil {
		return err
	}
	c := util.GetClient(false)
	ipcAddress, err := config.GetIPCAddress()
	if err != nil {
		return err
	}
	url := fmt.Sprintf("https://%v:%v/agent/config/list-runtime", ipcAddress, config.Datadog.GetInt("cmd_port"))
	r, err := util.DoGet(c, url)
	if err != nil {
		var errMap = make(map[string]string)
		json.Unmarshal(r, &errMap)
		// If the error has been marshalled into a json object, check it and return it properly
		if e, found := errMap["error"]; found {
			return fmt.Errorf(e)
		}
		return err
	}
	var settings = make(map[string]string)
	err = json.Unmarshal(r, &settings)
	if err != nil {
		return err
	}
	fmt.Println("=== Settings that can be changed at runtime ===")
	for setting, desc := range settings {
		fmt.Printf("%s:\t\t\t%s\n", setting, desc)
	}
	return nil
}

func setConfigValue(cmd *cobra.Command, args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("both setting name and value must be specified")
	}
	err := util.SetAuthToken()
	if err != nil {
		return err
	}
	c := util.GetClient(false)
	ipcAddress, err := config.GetIPCAddress()
	if err != nil {
		return err
	}
	url := fmt.Sprintf("https://%v:%v/agent/config/%v", ipcAddress, config.Datadog.GetInt("cmd_port"), args[0])
	body := fmt.Sprintf("value=%s", html.EscapeString(args[1]))
	r, err := util.DoPost(c, url, "application/x-www-form-urlencoded", bytes.NewBuffer([]byte(body)))
	if err != nil {
		var errMap = make(map[string]string)
		json.Unmarshal(r, &errMap)
		// If the error has been marshalled into a json object, check it and return it properly
		if e, found := errMap["error"]; found {
			return fmt.Errorf(e)
		}
		return err
	}
	fmt.Printf("Configuration setting %s is now set to: %s\n", args[0], args[1])
	return nil
}
