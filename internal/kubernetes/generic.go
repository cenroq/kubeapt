// Copyright by cenroq AG
// Contact: info@cenroq.com

package kubernetes

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/api/validate/content"
	"k8s.io/client-go/kubernetes"
)

func ListGenericResources(apiGroups, apiVersions, resources []string) ([]map[string]interface{}, error) {
	clientset, err := NewClientset()
	if err != nil {
		return nil, err
	}

	urls, err := draftURLs(clientset, apiGroups, apiVersions, resources)
	if err != nil {
		return nil, err
	}
	var returned []map[string]interface{}

	restClient := clientset.RESTClient()
	for _, url := range urls {
		result := restClient.Get().AbsPath(url).Do(context.TODO())
		if result.Error() != nil {
			continue
		}

		rawData, err := result.Raw()
		if err != nil {
			continue
		}

		var envelope map[string]any
		if err := json.Unmarshal(rawData, &envelope); err != nil {
			continue
		}

		items, ok := envelope["items"].([]interface{})
		if !ok {
			continue
		}

		listKind, _ := envelope["kind"].(string)
		listAPIVersion, _ := envelope["apiVersion"].(string)
		itemKind := strings.TrimSuffix(listKind, "List")

		for _, item := range items {
			obj, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			if _, hasKind := obj["kind"]; !hasKind && itemKind != "" {
				obj["kind"] = itemKind
			}
			if _, hasVersion := obj["apiVersion"]; !hasVersion && listAPIVersion != "" {
				obj["apiVersion"] = listAPIVersion
			}
			if _, ok := obj["metadata"].(map[string]interface{}); !ok {
				obj["metadata"] = map[string]interface{}{}
			}
			returned = append(returned, obj)
		}
	}

	return returned, nil
}

func ListResourcesForRules(rules []admissionregistrationv1.NamedRuleWithOperations) ([]map[string]interface{}, error) {
	var all []map[string]interface{}
	for _, rule := range rules {
		resources := extractPrimaryResources(rule.Resources)
		remote, err := ListGenericResources(rule.APIGroups, rule.APIVersions, resources)
		if err != nil {
			return nil, err
		}
		all = append(all, remote...)
	}
	return all, nil
}

func extractPrimaryResources(resources []string) []string {
	var out []string
	for _, res := range resources {
		if res == "" {
			continue
		}
		if idx := strings.IndexByte(res, '/'); idx != -1 {
			out = append(out, res[:idx])
		} else {
			out = append(out, res)
		}
	}
	if len(out) == 0 {
		return []string{"*"}
	}
	return out
}

// validateRuleSegments rejects resourceRules values that cannot be a single
// URL path segment.
//
// draftURLs joins these values straight into a request path, and the REST
// client cleans that path before sending it. A policy file with an apiGroup of
// "../api/v1/nodes/<node>/proxy" would therefore turn a list call into a node
// proxy request made with the operator's credentials. The API server never
// accepts such a value in a real ValidatingAdmissionPolicy, so it can only come
// from a local file, and rejecting it outright is safer than skipping it.
//
// "" (the core group) and "*" (expanded through discovery) remain valid.
func validateRuleSegments(apiGroups, apiVersions, resources []string) error {
	fields := []struct {
		name   string
		values []string
	}{
		{"apiGroups", apiGroups},
		{"apiVersions", apiVersions},
		{"resources", resources},
	}
	for _, field := range fields {
		for _, value := range field.values {
			if msgs := content.IsPathSegmentName(value); len(msgs) > 0 {
				return fmt.Errorf("invalid resourceRules %s value %q: %s", field.name, value, strings.Join(msgs, ", "))
			}
		}
	}
	return nil
}

type kubernetesQueryURL struct {
	apiGroup    string
	apiVersions []string
	resources   []string
}

func draftURLs(clientset *kubernetes.Clientset, apiGroups, apiVersions, resources []string) ([]string, error) {
	if err := validateRuleSegments(apiGroups, apiVersions, resources); err != nil {
		return nil, err
	}

	urlDrafts := make([]kubernetesQueryURL, 0)

	// Handle wildcard case "*" for apiGroups
	if len(apiGroups) == 1 && apiGroups[0] == "*" {
		groups, err := clientset.DiscoveryClient.ServerGroups()
		if err != nil {
			return nil, err
		}
		for _, group := range groups.Groups {
			urlDrafts = append(urlDrafts, kubernetesQueryURL{
				apiGroup: group.Name,
			})
		}
	} else {
		for _, group := range apiGroups {
			urlDrafts = append(urlDrafts, kubernetesQueryURL{
				apiGroup: group,
			})
		}
	}

	for i := range urlDrafts {
		if len(apiVersions) == 1 && apiVersions[0] == "*" {
			groups, err := clientset.DiscoveryClient.ServerGroups()
			if err != nil {
				return nil, err
			}
			for _, group := range groups.Groups {
				for _, version := range group.Versions {
					if urlDrafts[i].apiGroup == group.Name {
						urlDrafts[i].apiVersions = append(urlDrafts[i].apiVersions, version.Version)
					}
				}
			}
		} else {
			urlDrafts[i].apiVersions = apiVersions
		}

		if len(resources) == 1 && resources[0] == "*" {
			groups, err := clientset.DiscoveryClient.ServerGroups()
			if err != nil {
				return nil, err
			}
			for _, group := range groups.Groups {
				for _, version := range group.Versions {
					if urlDrafts[i].apiGroup == group.Name {
						resources, err := clientset.DiscoveryClient.ServerResourcesForGroupVersion(version.GroupVersion)
						if err != nil {
							return nil, err
						}
						for _, resource := range resources.APIResources {
							urlDrafts[i].resources = append(urlDrafts[i].resources, resource.Name)
						}
					}
				}
			}
		} else {
			urlDrafts[i].resources = resources
		}
	}

	urls := make([]string, 0)
	for _, urlDraft := range urlDrafts {
		for _, version := range urlDraft.apiVersions {
			for _, resource := range urlDraft.resources {
				if urlDraft.apiGroup == "" {
					urls = append(urls, "/api/"+version+"/"+resource)
				} else {
					urls = append(urls, "/apis/"+urlDraft.apiGroup+"/"+version+"/"+resource)
				}
			}
		}
	}

	return urls, nil
}
