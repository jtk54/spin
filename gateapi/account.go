/*
 * Spinnaker API
 *
 * No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)
 *
 * API version: 1.0.0
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */

package swagger

type Account struct {

	Permissions map[string][]string `json:"permissions,omitempty"`

	Name string `json:"name,omitempty"`

	Type_ string `json:"type,omitempty"`

	AccountId string `json:"accountId,omitempty"`

	Skin string `json:"skin,omitempty"`

	ProviderVersion string `json:"providerVersion,omitempty"`

	RequiredGroupMembership []string `json:"requiredGroupMembership,omitempty"`
}
