/*
Copyright 2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package services

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/gravitational/trace"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	kyaml "k8s.io/apimachinery/pkg/util/yaml"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/utils"
)

// AppGetter defines interface for fetching application resources.
type AppGetter interface {
	// GetApps returns all application resources.
	GetApps(context.Context) ([]types.Application, error)
	// GetApp returns the specified application resource.
	GetApp(ctx context.Context, name string) (types.Application, error)
}

// Apps defines an interface for managing application resources.
type Apps interface {
	// AppGetter provides methods for fetching application resources.
	AppGetter
	// CreateApp creates a new application resource.
	CreateApp(context.Context, types.Application) error
	// UpdateApp updates an existing application resource.
	UpdateApp(context.Context, types.Application) error
	// DeleteApp removes the specified application resource.
	DeleteApp(ctx context.Context, name string) error
	// DeleteAllApps removes all database resources.
	DeleteAllApps(context.Context) error
}

// MarshalApp marshals Application resource to JSON.
func MarshalApp(app types.Application, opts ...MarshalOption) ([]byte, error) {
	if err := app.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	switch app := app.(type) {
	case *types.AppV3:
		if !cfg.PreserveResourceID {
			copy := *app
			copy.SetResourceID(0)
			copy.SetRevision("")
			app = &copy
		}
		return utils.FastMarshal(app)
	default:
		return nil, trace.BadParameter("unsupported app resource %T", app)
	}
}

// UnmarshalApp unmarshals Application resource from JSON.
func UnmarshalApp(data []byte, opts ...MarshalOption) (types.Application, error) {
	if len(data) == 0 {
		return nil, trace.BadParameter("missing app resource data")
	}
	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var h types.ResourceHeader
	if err := utils.FastUnmarshal(data, &h); err != nil {
		return nil, trace.Wrap(err)
	}
	switch h.Version {
	case types.V3:
		var app types.AppV3
		if err := utils.FastUnmarshal(data, &app); err != nil {
			return nil, trace.BadParameter(err.Error())
		}
		if err := app.CheckAndSetDefaults(); err != nil {
			return nil, trace.Wrap(err)
		}
		if cfg.ID != 0 {
			app.SetResourceID(cfg.ID)
		}
		if cfg.Revision != "" {
			app.SetRevision(cfg.Revision)
		}
		if !cfg.Expires.IsZero() {
			app.SetExpiry(cfg.Expires)
		}
		return &app, nil
	}
	return nil, trace.BadParameter("unsupported app resource version %q", h.Version)
}

// MarshalAppServer marshals the AppServer resource to JSON.
func MarshalAppServer(appServer types.AppServer, opts ...MarshalOption) ([]byte, error) {
	if err := appServer.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	switch appServer := appServer.(type) {
	case *types.AppServerV3:
		if !cfg.PreserveResourceID {
			copy := *appServer
			copy.SetResourceID(0)
			copy.SetRevision("")
			appServer = &copy
		}
		return utils.FastMarshal(appServer)
	default:
		return nil, trace.BadParameter("unsupported app server resource %T", appServer)
	}
}

// UnmarshalAppServer unmarshals AppServer resource from JSON.
func UnmarshalAppServer(data []byte, opts ...MarshalOption) (types.AppServer, error) {
	if len(data) == 0 {
		return nil, trace.BadParameter("missing app server data")
	}
	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var h types.ResourceHeader
	if err := utils.FastUnmarshal(data, &h); err != nil {
		return nil, trace.Wrap(err)
	}
	switch h.Version {
	case types.V3:
		var s types.AppServerV3
		if err := utils.FastUnmarshal(data, &s); err != nil {
			return nil, trace.BadParameter(err.Error())
		}
		if err := s.CheckAndSetDefaults(); err != nil {
			return nil, trace.Wrap(err)
		}
		if cfg.ID != 0 {
			s.SetResourceID(cfg.ID)
		}
		if cfg.Revision != "" {
			s.SetRevision(cfg.Revision)
		}
		if !cfg.Expires.IsZero() {
			s.SetExpiry(cfg.Expires)
		}
		return &s, nil
	}
	return nil, trace.BadParameter("unsupported app server resource version %q", h.Version)
}

// NewApplicationFromKubeService creates application resources from kubernetes service.
// It transforms service fields and annotations into appropriate Teleport app fields.
// Service labels are copied to app labels.
func NewApplicationFromKubeService(service corev1.Service, clusterName, protocol string, port corev1.ServicePort) (types.Application, error) {
	appURI := buildAppURI(protocol, GetServiceFQDN(service), port.Port)

	rewriteConfig, err := getAppRewriteConfig(service.GetAnnotations())
	if err != nil {
		return nil, trace.Wrap(err, "could not get app rewrite config for the service")
	}

	appNameAnnotation := service.GetAnnotations()[types.DiscoveryAppNameLabel]
	appName, err := getAppName(service.GetName(), service.GetNamespace(), clusterName, port.Name, appNameAnnotation)
	if err != nil {
		return nil, trace.Wrap(err, "could not create app name for the service")
	}

	labels, err := getAppLabels(service.GetLabels(), clusterName)
	if err != nil {
		return nil, trace.Wrap(err, "could not get labels for the service")
	}

	app, err := types.NewAppV3(types.Metadata{
		Name:        appName,
		Description: fmt.Sprintf("Discovered application in Kubernetes cluster %q", clusterName),
		Labels:      labels,
	}, types.AppSpecV3{
		URI:                appURI,
		Rewrite:            rewriteConfig,
		InsecureSkipVerify: getTLSInsecureSkipVerify(service.GetAnnotations()),
	})
	if err != nil {
		return nil, trace.Wrap(err, "could not create an app from Kubernetes service")
	}

	return app, nil
}

// GetServiceFQDN returns the fully qualified domain name for the service.
func GetServiceFQDN(service corev1.Service) string {
	// If service type is ExternalName it points to external DNS name, to keep correct
	// HOST for HTTP requests we return already final external DNS name.
	// https://kubernetes.io/docs/concepts/services-networking/service/#externalname
	if service.Spec.Type == corev1.ServiceTypeExternalName {
		return service.Spec.ExternalName
	}
	return fmt.Sprintf("%s.%s.svc.%s", service.GetName(), service.GetNamespace(), clusterDomainResolver())
}

func buildAppURI(protocol, serviceFQDN string, port int32) string {
	return (&url.URL{
		Scheme: protocol,
		Host:   fmt.Sprintf("%s:%d", serviceFQDN, port),
	}).String()
}

func getAppRewriteConfig(annotations map[string]string) (*types.Rewrite, error) {
	rewritePayload := annotations[types.DiscoveryAppRewriteLabel]
	if rewritePayload == "" {
		return nil, nil
	}

	rw := types.Rewrite{}
	reader := strings.NewReader(rewritePayload)
	decoder := kyaml.NewYAMLOrJSONDecoder(reader, 32*1024)
	err := decoder.Decode(&rw)
	if err != nil {
		return nil, trace.Wrap(err, "failed decoding rewrite config")
	}

	return &rw, nil
}

func getTLSInsecureSkipVerify(annotations map[string]string) bool {
	val := annotations[types.DiscoveryAppInsecureSkipVerify]
	if val == "" {
		return false
	}
	return val == "true"
}

func getAppName(serviceName, namespace, clusterName, portName, nameAnnotation string) (string, error) {
	if nameAnnotation != "" {
		name := nameAnnotation
		if portName != "" {
			name = fmt.Sprintf("%s-%s", name, portName)
		}

		if len(validation.IsDNS1035Label(name)) > 0 {
			return "", trace.BadParameter(
				"application name %q must be a valid DNS subdomain: https://goteleport.com/docs/application-access/guides/connecting-apps/#application-name", name)
		}

		return name, nil
	}

	clusterName = strings.ReplaceAll(clusterName, ".", "-")
	if portName != "" {
		return fmt.Sprintf("%s-%s-%s-%s", serviceName, portName, namespace, clusterName), nil
	}
	return fmt.Sprintf("%s-%s-%s", serviceName, namespace, clusterName), nil
}

func getAppLabels(serviceLabels map[string]string, clusterName string) (map[string]string, error) {
	result := make(map[string]string, len(serviceLabels)+1)

	for k, v := range serviceLabels {
		if !types.IsValidLabelKey(k) {
			return nil, trace.BadParameter("invalid label key: %q", k)
		}

		result[k] = v
	}
	result[types.KubernetesClusterLabel] = clusterName

	return result, nil
}

var (
	// clusterDomainResolver is a function that resolves the cluster domain once and caches the result.
	// It's used to lazily resolve the cluster domain from the env var "TELEPORT_KUBE_CLUSTER_DOMAIN" or fallback to
	// a default value.
	// It's only used when agent is running in the Kubernetes cluster.
	clusterDomainResolver = sync.OnceValue[string](getClusterDomain)
)

const (
	// teleportKubeClusterDomain is the environment variable that specifies the cluster domain.
	teleportKubeClusterDomain = "TELEPORT_KUBE_CLUSTER_DOMAIN"
)

func getClusterDomain() string {
	if envDomain := os.Getenv(teleportKubeClusterDomain); envDomain != "" {
		return envDomain
	}
	return "cluster.local"
}
