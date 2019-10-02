// Copyright (c) 2019, Waze, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

package canary_config

import (
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spinnaker/spin/cmd/gateclient"
	"github.com/spinnaker/spin/util"
	"net/http"
)

type RetroOptions struct {
	*canaryConfigOptions
	output             string
	canaryConfigFile   string
	controlGroup       string
	controlLocation    string
	experimentGroup    string
	experimentLocation string
	startInstant       string
	endInstant         string
}

const (
	retroTemplateShort = "Retro the provided canary config"
	retroTemplateLong  = "Retro the provided canary config"
)

func NewRetroCmd(canaryConfigOptions canaryConfigOptions) *cobra.Command {
	options := RetroOptions{
		canaryConfigOptions: &canaryConfigOptions,
	}
	cmd := &cobra.Command{
		Use:     "retro",
		Aliases: []string{},
		Short:   retroTemplateShort,
		Long:    retroTemplateLong,
		RunE: func(cmd *cobra.Command, args []string) error {
			return retroCanaryConfig(cmd, options)
		},
	}

	cmd.PersistentFlags().StringVarP(&options.canaryConfigFile, "file",
		"f", "", "path to the canary config file")
	cmd.PersistentFlags().StringVar(&options.controlGroup, "control-group", "", "Control server group name")
	cmd.PersistentFlags().StringVar(&options.controlLocation, "control-location", "", "Control server group location")
	cmd.PersistentFlags().StringVar(&options.experimentGroup, "experiment-group", "", "Experiment server group name")
	cmd.PersistentFlags().StringVar(&options.experimentLocation, "experiment-location", "", "Experiment server group location")
	cmd.PersistentFlags().StringVar(&options.startInstant, "start", "", "Start of canary window, in ISO Instant format")
	cmd.PersistentFlags().StringVar(&options.endInstant, "end", "", "End of canary window, in ISO Instant format")

	return cmd
}

func retroCanaryConfig(cmd *cobra.Command, options RetroOptions) error {
	gateClient, err := gateclient.NewGateClient(cmd.InheritedFlags())
	if err != nil {
		return err
	}

	canaryConfigJson, err := util.ParseJsonFromFileOrStdin(options.canaryConfigFile, false)
	if err != nil {
		return err
	}

	if _, exists := canaryConfigJson["id"]; !exists {
		util.UI.Error("Required canary config key 'id' missing...\n")
		return fmt.Errorf("Submitted canary config is invalid: %s\n", templateJson)
	}

	if options.controlGroup == "" || options.controlLocation == "" ||
		options.experimentGroup == "" || options.experimentLocation == "" ||
		options.startInstant == "" || options.endInstant == "" {
		return errors.New("Required retro flag not supplied.\n")
	}

	canaryConfigId := templateJson["id"].(string)

	scopes := map[string]interface{}{
		"blah": map[string]interface{}{
			"controlScope": map[string]interface{}{
				"scope":    options.controlGroup, // Parameterize.
				"location": options.controlLocation,
				"start":    options.startInstant,
				"end":      options.endInstant,
				"step":     10, // TODO(jacobkiefer): Step format?
			},
			"experimentScope": map[string]interface{}{
				"scope":    options.experimentGroup,
				"location": options.experimentLocation,
				"start":    options.startInstant,
				"end":      options.endInstant,
				"step":     10,
			},
		},
	}

	executionRequest := map[string]interface{}{
		"scopes": scopes,
		"thresholds": map[string]int{
			"pass":     95, // Parameterize pass and marginal?
			"marginal": 75,
		},
	}

	canaryExecutionResp, resp, initiateErr := gateClient.V2CanaryControllerApi.InitiateCanaryUsingPOST(gateClient.Context, canaryConfigId, executionRequest, map[string]interface{}{})

	if resp.StatusCode == http.StatusOK {
		canaryExecutionId := canaryExecutionResp["canaryExecutionId"]
		derp, resp, err := gateClient.V2CanaryControllerApi.GetCanaryResultUsingGET(gateClient.Context, canaryConfigId, canaryExecutionId, map[string]interface{}{})
		for derp == nil && err == nil {
			derp, resp, err = gateClient.V2CanaryControllerApi.GetCanaryResultUsingGET(gateClient.Context, canaryConfigId, canaryExecutionId, map[string]interface{}{})
		}
		if err != nil {
			return err
		}
		// TODO(jacobkiefer): Great success?
	} else {
		if initiateErr != nil {
			return initiateErr
		}
		return fmt.Errorf(
			"Encountered an unexpected status code %d querying canary config with id %s\n", resp.StatusCode, canaryConfigId)
	}

	// if resp.StatusCode == http.StatusOK {
	// 	_, retroResp, retroErr = gateClient.V2CanaryConfigControllerApi.UpdateCanaryConfigUsingPUT(
	// 		gateClient.Context, templateJson, templateId, map[string]interface{}{})
	// } else if resp.StatusCode == http.StatusNotFound {
	// 	_, retroResp, retroErr = gateClient.V2CanaryConfigControllerApi.CreateCanaryConfigUsingPOST(
	// 		gateClient.Context, templateJson, map[string]interface{}{})
	// } else {
	// 	if queryErr != nil {
	// 		return queryErr
	// 	}
	// 	return fmt.Errorf(
	// 		"Encountered an unexpected status code %d querying canary config with id %s\n",
	// 		resp.StatusCode, templateId)
	// }

	// if retroErr != nil {
	// 	return retroErr
	// }

	// if retroResp.StatusCode != http.StatusOK {
	// 	return fmt.Errorf(
	// 		"Encountered an error saving canary config %v, status code: %d\n",
	// 		templateJson, retroResp.StatusCode)
	// }

	// util.UI.Info(util.Colorize().Color(fmt.Sprintf("[reset][bold][green]Canary config retro succeeded")))
	return nil
}
