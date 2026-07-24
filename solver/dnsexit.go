/*
Copyright 2026 Fabricio Martinez

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

package solver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	acmev1alpha1 "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// dnsexitTTLMinutes is the TTL sent with every TXT record.
//
// The DNSExit API's "ttl" field is expressed in MINUTES and is multiplied by 60
// server-side. It must be >= 1; sending 0 is rejected with:
//
//	{"code":3,"message":"Missing Required Parameters - ttl must be >= 1 ..."}
//
// 1 minute (60s) is the shortest value DNSExit accepts and is what we want for
// ACME, so that stale _acme-challenge records fall out of resolver caches fast.
const dnsexitTTLMinutes = 1

type DNSExitSolver struct {
	kubeClient kubernetes.Interface
}

type SecretKeySelector struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

type Config struct {
	APIKeySecretRef SecretKeySelector `json:"apiKeySecretRef"`
}

func (s *DNSExitSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	client, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}
	s.kubeClient = client
	return nil
}

func (s *DNSExitSolver) Name() string {
	return "dnsexit"
}

func (s *DNSExitSolver) Present(ch *acmev1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch)
	if err != nil {
		return err
	}

	apiKey, err := s.getSecretValue(ch.ResourceNamespace, cfg.APIKeySecretRef)
	if err != nil {
		return err
	}

	recordName, zone := computeRecordNameAndZone(ch.ResolvedFQDN, ch.ResolvedZone)
	return createTXT(apiKey, zone, recordName, ch.Key)
}

func (s *DNSExitSolver) CleanUp(ch *acmev1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch)
	if err != nil {
		return err
	}

	apiKey, err := s.getSecretValue(ch.ResourceNamespace, cfg.APIKeySecretRef)
	if err != nil {
		return err
	}

	recordName, zone := computeRecordNameAndZone(ch.ResolvedFQDN, ch.ResolvedZone)
	return deleteTXT(apiKey, zone, recordName, ch.Key)
}

func loadConfig(ch *acmev1alpha1.ChallengeRequest) (*Config, error) {
	cfg := &Config{}
	if err := json.Unmarshal(ch.Config.Raw, cfg); err != nil {
		return nil, fmt.Errorf("unable to decode solver config: %w", err)
	}
	return cfg, nil
}

func (s *DNSExitSolver) getSecretValue(namespace string, selector SecretKeySelector) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	secret, err := s.kubeClient.CoreV1().
		Secrets(namespace).
		Get(ctx, selector.Name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("unable to read secret %s/%s: %w", namespace, selector.Name, err)
	}

	value, ok := secret.Data[selector.Key]
	if !ok {
		return "", fmt.Errorf("key %q not found in secret %s/%s", selector.Key, namespace, selector.Name)
	}

	return string(value), nil
}

func computeRecordNameAndZone(resolvedFQDN, resolvedZone string) (recordName, zone string) {
	fqdn := strings.TrimSuffix(resolvedFQDN, ".")
	z := strings.TrimSuffix(resolvedZone, ".")

	if z != "" && fqdn != z && strings.HasSuffix(fqdn, "."+z) {
		recordName = strings.TrimSuffix(fqdn, "."+z)
		zone = z
		return recordName, zone
	}

	parts := strings.SplitN(fqdn, ".", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return fqdn, ""
}

func createTXT(apiKey, zone, name, value string) error {
	if zone == "" {
		return fmt.Errorf("empty zone derived from resolved values (zone=%q name=%q)", zone, name)
	}

	payload := map[string]interface{}{
		"domain": zone,
		"add": map[string]interface{}{
			"type":    "TXT",
			"name":    name,
			"content": value,
			// TTL in minutes, must be >= 1. See dnsexitTTLMinutes.
			"ttl": dnsexitTTLMinutes,
			// overwrite MUST be false: apex + wildcard certs place two different
			// TXT values at the same _acme-challenge name and both must coexist
			// for ACME validation. overwrite:true clobbers the first value.
			"overwrite": false,
		},
	}

	return dnsexitPost(apiKey, payload, "create")
}

func deleteTXT(apiKey, zone, name, value string) error {
	if zone == "" {
		return fmt.Errorf("empty zone derived from resolved values (zone=%q name=%q)", zone, name)
	}

	payload := map[string]interface{}{
		"domain": zone,
		"delete": map[string]interface{}{
			"type": "TXT",
			"name": name,
			// content MUST be set. createTXT uses overwrite:false, so an
			// apex + wildcard certificate leaves two TXT values on the same
			// _acme-challenge name. Deleting by name alone removes both and
			// breaks the challenge that is still pending validation.
			"content": value,
		},
	}

	return dnsexitPost(apiKey, payload, "delete")
}

func dnsexitPost(apiKey string, payload map[string]interface{}, action string) error {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	fmt.Printf("[DNSEXIT] Sending %s payload: %s\n", action, string(jsonData))

	req, err := http.NewRequest("POST", "https://api.dnsexit.com/dns/", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("apikey", apiKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	fmt.Printf("[DNSEXIT] Response status: %d, body: %s\n", resp.StatusCode, string(body))

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("DNSExit %s failed: HTTP %s - %s", action, resp.Status, string(body))
	}

	// DNSExit returns HTTP 200 even on logical failures; the JSON "code" field is
	// authoritative (0 = success, anything else = error). See https://dnsexit.com/dns/dns-api/
	var r struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return fmt.Errorf("DNSExit %s: unparseable response: %s", action, string(body))
	}
	if r.Code != 0 {
		return fmt.Errorf("DNSExit %s failed: code=%d msg=%q", action, r.Code, r.Message)
	}

	return nil
}
