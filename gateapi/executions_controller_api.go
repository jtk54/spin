/*
 * Spinnaker API
 *
 * No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)
 *
 * API version: 1.0.0
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */

package swagger

import (
	"io/ioutil"
	"net/url"
	"net/http"
	"strings"
	"golang.org/x/net/context"
	"encoding/json"
	"fmt"
)

// Linger please
var (
	_ context.Context
)

type ExecutionsControllerApiService service


/* ExecutionsControllerApiService Retrieves an ad-hoc collection of executions based on a number of user-supplied parameters. Either executionIds or pipelineConfigIds must be supplied in order to return any results. If both are supplied, an exception will be thrown.
 * @param ctx context.Context for authentication, logging, tracing, etc.
 @param optional (nil or map[string]interface{}) with one or more of:
     @param "pipelineConfigIds" (string) A comma-separated list of pipeline configuration IDs to retrieve recent executions for. Either this OR pipelineConfigIds must be supplied, but not both.
     @param "executionIds" (string) A comma-separated list of executions to retrieve. Either this OR pipelineConfigIds must be supplied, but not both.
     @param "limit" (int32) The number of executions to return per pipeline configuration. Ignored if executionIds parameter is supplied. If this value is missing, it is defaulted to 1.
     @param "statuses" (string) A comma-separated list of execution statuses to filter by. Ignored if executionIds parameter is supplied. If this value is missing, it is defaulted to all statuses.
     @param "expand" (bool) Expands each execution object in the resulting list. If this value is missing, it is defaulted to true.
 @return []interface{}*/
func (a *ExecutionsControllerApiService) GetLatestExecutionsByConfigIdsUsingGET(ctx context.Context, localVarOptionals map[string]interface{}) ([]interface{},  *http.Response, error) {
	var (
		localVarHttpMethod = strings.ToUpper("Get")
		localVarPostBody interface{}
		localVarFileName string
		localVarFileBytes []byte
	 	successPayload  []interface{}
	)

	// create path and map variables
	localVarPath := a.client.cfg.BasePath + "/executions"

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	if err := typeCheckParameter(localVarOptionals["pipelineConfigIds"], "string", "pipelineConfigIds"); err != nil {
		return successPayload, nil, err
	}
	if err := typeCheckParameter(localVarOptionals["executionIds"], "string", "executionIds"); err != nil {
		return successPayload, nil, err
	}
	if err := typeCheckParameter(localVarOptionals["limit"], "int32", "limit"); err != nil {
		return successPayload, nil, err
	}
	if err := typeCheckParameter(localVarOptionals["statuses"], "string", "statuses"); err != nil {
		return successPayload, nil, err
	}
	if err := typeCheckParameter(localVarOptionals["expand"], "bool", "expand"); err != nil {
		return successPayload, nil, err
	}

	if localVarTempParam, localVarOk := localVarOptionals["pipelineConfigIds"].(string); localVarOk {
		localVarQueryParams.Add("pipelineConfigIds", parameterToString(localVarTempParam, ""))
	}
	if localVarTempParam, localVarOk := localVarOptionals["executionIds"].(string); localVarOk {
		localVarQueryParams.Add("executionIds", parameterToString(localVarTempParam, ""))
	}
	if localVarTempParam, localVarOk := localVarOptionals["limit"].(int32); localVarOk {
		localVarQueryParams.Add("limit", parameterToString(localVarTempParam, ""))
	}
	if localVarTempParam, localVarOk := localVarOptionals["statuses"].(string); localVarOk {
		localVarQueryParams.Add("statuses", parameterToString(localVarTempParam, ""))
	}
	if localVarTempParam, localVarOk := localVarOptionals["expand"].(bool); localVarOk {
		localVarQueryParams.Add("expand", parameterToString(localVarTempParam, ""))
	}
	// to determine the Content-Type header
	localVarHttpContentTypes := []string{ "application/json",  }

	// set Content-Type header
	localVarHttpContentType := selectHeaderContentType(localVarHttpContentTypes)
	if localVarHttpContentType != "" {
		localVarHeaderParams["Content-Type"] = localVarHttpContentType
	}

	// to determine the Accept header
	localVarHttpHeaderAccepts := []string{
		"*/*",
		}

	// set Accept header
	localVarHttpHeaderAccept := selectHeaderAccept(localVarHttpHeaderAccepts)
	if localVarHttpHeaderAccept != "" {
		localVarHeaderParams["Accept"] = localVarHttpHeaderAccept
	}
	r, err := a.client.prepareRequest(ctx, localVarPath, localVarHttpMethod, localVarPostBody, localVarHeaderParams, localVarQueryParams, localVarFormParams, localVarFileName, localVarFileBytes)
	if err != nil {
		return successPayload, nil, err
	}

	localVarHttpResponse, err := a.client.callAPI(r)
	if err != nil || localVarHttpResponse == nil {
		return successPayload, localVarHttpResponse, err
	}
	defer localVarHttpResponse.Body.Close()
	if localVarHttpResponse.StatusCode >= 300 {
		bodyBytes, _ := ioutil.ReadAll(localVarHttpResponse.Body)
		return successPayload, localVarHttpResponse, reportError("Status: %v, Body: %s", localVarHttpResponse.Status, bodyBytes)
	}

	if err = json.NewDecoder(localVarHttpResponse.Body).Decode(&successPayload); err != nil {
		return successPayload, localVarHttpResponse, err
	}


	return successPayload, localVarHttpResponse, err
}

/* ExecutionsControllerApiService Search for pipeline executions using a combination of criteria. The returned list is sorted by buildTime (trigger time) in reverse order so that newer executions are first in the list.
 * @param ctx context.Context for authentication, logging, tracing, etc.
 @param application Only includes executions that are part of this application. If this value is \&quot;*\&quot;, results will include executions of all applications.
 @param optional (nil or map[string]interface{}) with one or more of:
     @param "triggerTypes" (string) Only includes executions that were triggered by a trigger with a type that is equal to a type provided in this field. The list of trigger types should be a comma-delimited string. If this value is missing, results will includes executions of all trigger types.
     @param "pipelineName" (string) Only includes executions that with this pipeline name.
     @param "eventId" (string) Only includes executions that were triggered by a trigger with this eventId.
     @param "trigger" (string) Only includes executions that were triggered by a trigger that matches the subset of fields provided by this value. This value should be a base64-encoded string of a JSON representation of a trigger object. The comparison succeeds if the execution trigger contains all the fields of the input trigger, the fields are of the same type, and each value of the field \&quot;matches\&quot;. The term \&quot;matches\&quot; is specific for each field&#39;s type: - For Strings: A String value in the execution&#39;s trigger matches the input trigger&#39;s String value if the former equals the latter (case-insensitive) OR if the former matches the latter as a regular expression. - For Maps: A Map value in the execution&#39;s trigger matches the input trigger&#39;s Map value if the former contains all keys of the latter and their values match. - For Collections: A Collection value in the execution&#39;s trigger matches the input trigger&#39;s Collection value if the former has a unique element that matches each element of the latter. - Every other value is compared using the Java \&quot;equals\&quot; method (Groovy \&quot;&#x3D;&#x3D;\&quot; operator)
     @param "triggerTimeStartBoundary" (int64) Only includes executions that were built at or after the given time, represented as a Unix timestamp in ms (UTC). This value must be &gt;&#x3D; 0 and &lt;&#x3D; the value of [triggerTimeEndBoundary], if provided. If this value is missing, it is defaulted to 0.
     @param "triggerTimeEndBoundary" (int64) Only includes executions that were built at or before the given time, represented as a Unix timestamp in ms (UTC). This value must be &lt;&#x3D; 9223372036854775807 (Long.MAX_VALUE) and &gt;&#x3D; the value of [triggerTimeStartBoundary], if provided. If this value is missing, it is defaulted to 9223372036854775807.
     @param "statuses" (string) Only includes executions with a status that is equal to a status provided in this field. The list of statuses should be given as a comma-delimited string. If this value is missing, includes executions of all statuses. Allowed statuses are: NOT_STARTED, RUNNING, PAUSED, SUSPENDED, SUCCEEDED, FAILED_CONTINUE, TERMINAL, CANCELED, REDIRECT, STOPPED, SKIPPED, BUFFERED.
     @param "startIndex" (int32) Sets the first item of the resulting list for pagination. The list is 0-indexed. This value must be &gt;&#x3D; 0. If this value is missing, it is defaulted to 0.
     @param "size" (int32) Sets the size of the resulting list for pagination. This value must be &gt; 0. If this value is missing, it is defaulted to 10.
     @param "reverse" (bool) Reverses the resulting list before it is paginated. If this value is missing, it is defaulted to false.
     @param "expand" (bool) Expands each execution object in the resulting list. If this value is missing, it is defaulted to false.
 @return []interface{}*/
func (a *ExecutionsControllerApiService) SearchForPipelineExecutionsByTriggerUsingGET(ctx context.Context, application string, localVarOptionals map[string]interface{}) ([]interface{},  *http.Response, error) {
	var (
		localVarHttpMethod = strings.ToUpper("Get")
		localVarPostBody interface{}
		localVarFileName string
		localVarFileBytes []byte
	 	successPayload  []interface{}
	)

	// create path and map variables
	localVarPath := a.client.cfg.BasePath + "/applications/{application}/executions/search"
	localVarPath = strings.Replace(localVarPath, "{"+"application"+"}", fmt.Sprintf("%v", application), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	if err := typeCheckParameter(localVarOptionals["triggerTypes"], "string", "triggerTypes"); err != nil {
		return successPayload, nil, err
	}
	if err := typeCheckParameter(localVarOptionals["pipelineName"], "string", "pipelineName"); err != nil {
		return successPayload, nil, err
	}
	if err := typeCheckParameter(localVarOptionals["eventId"], "string", "eventId"); err != nil {
		return successPayload, nil, err
	}
	if err := typeCheckParameter(localVarOptionals["trigger"], "string", "trigger"); err != nil {
		return successPayload, nil, err
	}
	if err := typeCheckParameter(localVarOptionals["triggerTimeStartBoundary"], "int64", "triggerTimeStartBoundary"); err != nil {
		return successPayload, nil, err
	}
	if err := typeCheckParameter(localVarOptionals["triggerTimeEndBoundary"], "int64", "triggerTimeEndBoundary"); err != nil {
		return successPayload, nil, err
	}
	if err := typeCheckParameter(localVarOptionals["statuses"], "string", "statuses"); err != nil {
		return successPayload, nil, err
	}
	if err := typeCheckParameter(localVarOptionals["startIndex"], "int32", "startIndex"); err != nil {
		return successPayload, nil, err
	}
	if err := typeCheckParameter(localVarOptionals["size"], "int32", "size"); err != nil {
		return successPayload, nil, err
	}
	if err := typeCheckParameter(localVarOptionals["reverse"], "bool", "reverse"); err != nil {
		return successPayload, nil, err
	}
	if err := typeCheckParameter(localVarOptionals["expand"], "bool", "expand"); err != nil {
		return successPayload, nil, err
	}

	if localVarTempParam, localVarOk := localVarOptionals["triggerTypes"].(string); localVarOk {
		localVarQueryParams.Add("triggerTypes", parameterToString(localVarTempParam, ""))
	}
	if localVarTempParam, localVarOk := localVarOptionals["pipelineName"].(string); localVarOk {
		localVarQueryParams.Add("pipelineName", parameterToString(localVarTempParam, ""))
	}
	if localVarTempParam, localVarOk := localVarOptionals["eventId"].(string); localVarOk {
		localVarQueryParams.Add("eventId", parameterToString(localVarTempParam, ""))
	}
	if localVarTempParam, localVarOk := localVarOptionals["trigger"].(string); localVarOk {
		localVarQueryParams.Add("trigger", parameterToString(localVarTempParam, ""))
	}
	if localVarTempParam, localVarOk := localVarOptionals["triggerTimeStartBoundary"].(int64); localVarOk {
		localVarQueryParams.Add("triggerTimeStartBoundary", parameterToString(localVarTempParam, ""))
	}
	if localVarTempParam, localVarOk := localVarOptionals["triggerTimeEndBoundary"].(int64); localVarOk {
		localVarQueryParams.Add("triggerTimeEndBoundary", parameterToString(localVarTempParam, ""))
	}
	if localVarTempParam, localVarOk := localVarOptionals["statuses"].(string); localVarOk {
		localVarQueryParams.Add("statuses", parameterToString(localVarTempParam, ""))
	}
	if localVarTempParam, localVarOk := localVarOptionals["startIndex"].(int32); localVarOk {
		localVarQueryParams.Add("startIndex", parameterToString(localVarTempParam, ""))
	}
	if localVarTempParam, localVarOk := localVarOptionals["size"].(int32); localVarOk {
		localVarQueryParams.Add("size", parameterToString(localVarTempParam, ""))
	}
	if localVarTempParam, localVarOk := localVarOptionals["reverse"].(bool); localVarOk {
		localVarQueryParams.Add("reverse", parameterToString(localVarTempParam, ""))
	}
	if localVarTempParam, localVarOk := localVarOptionals["expand"].(bool); localVarOk {
		localVarQueryParams.Add("expand", parameterToString(localVarTempParam, ""))
	}
	// to determine the Content-Type header
	localVarHttpContentTypes := []string{ "application/json",  }

	// set Content-Type header
	localVarHttpContentType := selectHeaderContentType(localVarHttpContentTypes)
	if localVarHttpContentType != "" {
		localVarHeaderParams["Content-Type"] = localVarHttpContentType
	}

	// to determine the Accept header
	localVarHttpHeaderAccepts := []string{
		"*/*",
		}

	// set Accept header
	localVarHttpHeaderAccept := selectHeaderAccept(localVarHttpHeaderAccepts)
	if localVarHttpHeaderAccept != "" {
		localVarHeaderParams["Accept"] = localVarHttpHeaderAccept
	}
	r, err := a.client.prepareRequest(ctx, localVarPath, localVarHttpMethod, localVarPostBody, localVarHeaderParams, localVarQueryParams, localVarFormParams, localVarFileName, localVarFileBytes)
	if err != nil {
		return successPayload, nil, err
	}

	localVarHttpResponse, err := a.client.callAPI(r)
	if err != nil || localVarHttpResponse == nil {
		return successPayload, localVarHttpResponse, err
	}
	defer localVarHttpResponse.Body.Close()
	if localVarHttpResponse.StatusCode >= 300 {
		bodyBytes, _ := ioutil.ReadAll(localVarHttpResponse.Body)
		return successPayload, localVarHttpResponse, reportError("Status: %v, Body: %s", localVarHttpResponse.Status, bodyBytes)
	}

	if err = json.NewDecoder(localVarHttpResponse.Body).Decode(&successPayload); err != nil {
		return successPayload, localVarHttpResponse, err
	}


	return successPayload, localVarHttpResponse, err
}

