// SPDX-License-Identifier: MIT
// Copyright (c) 2023 Erik Junsved

package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

const (
	cloudflareAPI = "https://api.cloudflare.com/client/v4/zones/"
	port          = 25
	protocol      = "tcp"

	// If the values below are modified,
	// the generateCert function also needs
	// to be modified to reflect the changes.
	usage        = 3
	selector     = 1
	matchingType = 1
)

type tlsaRecordsResponse struct {
	Result []tlsaRecord `json:"result"`
}

type tlsaRecord struct {
	ID   string   `json:"id"`
	Data tlsaData `json:"data"`
}

type tlsaData struct {
	Certificate  string `json:"certificate"`
	MatchingType int    `json:"matching_type"`
	Selector     int    `json:"selector"`
	Usage        int    `json:"usage"`
}

func main() {
	requiredEnvVars := []string{"KEY_FILE", "KEY_FILE_NEXT", "ZONE_ID", "API_TOKEN", "DOMAIN"}
	for _, envVar := range requiredEnvVars {
		if os.Getenv(envVar) == "" {
			log.Fatalln("Fatal:", envVar, "environment variable is not defined")
		}
	}

	cert, err := generateCert(os.Getenv("KEY_FILE"))
	if err != nil {
		log.Fatalln("Fatal: failed to generate current cert:", err)
	}

	certNext, err := generateCert(os.Getenv("KEY_FILE_NEXT"))
	if err != nil {
		log.Fatalln("Fatal: failed to generate next cert:", err)
	}

	log.Println("Current cert:", cert)
	log.Println("Next cert:", certNext)

	tlsaRecords, err := getTLSARecords()
	if err != nil {
		log.Fatalln("Fatal: failed to get TLSA records:", err)
	}

	for i, record := range tlsaRecords {
		log.Printf("DNS record %d: ID: %s, cert: %s\n", i+1, record.ID, record.Data.Certificate)
	}

	if len(tlsaRecords) != 2 {
		log.Println("Incorrect number of DNS entries. Deleting them and generating new ones.")

		err = deleteAll(tlsaRecords)
		if err != nil {
			log.Fatalln("Fatal: failed to delete all TLSA recors:", err)
		}

		err = addRequest(certNext)
		if err != nil {
			log.Fatalln("Fatal: failed to add TLSA record for current cert:", err)
		}

		err = addRequest(cert)
		if err != nil {
			log.Fatalln("Fatal: failed to add TLSA record for next cert:", err)
		}

		os.Exit(0)
	}

	switch {
	case (checkData(tlsaRecords[0], cert) && checkData(tlsaRecords[1], certNext)) ||
		(checkData(tlsaRecords[0], certNext) && checkData(tlsaRecords[1], cert)):
		log.Println("Nothing to do!")
	case checkData(tlsaRecords[0], cert):
		err = modifyRequest(certNext, tlsaRecords[1].ID)
	case checkData(tlsaRecords[0], certNext):
		err = modifyRequest(cert, tlsaRecords[1].ID)
	case checkData(tlsaRecords[1], cert):
		err = modifyRequest(certNext, tlsaRecords[0].ID)
	case checkData(tlsaRecords[1], certNext):
		err = modifyRequest(cert, tlsaRecords[0].ID)
	default:
		err = modifyRequest(certNext, tlsaRecords[1].ID)
		if err != nil {
			break
		}
		err = modifyRequest(cert, tlsaRecords[0].ID)
	}
	if err != nil {
		log.Fatalln("Fatal: failed to modify TLSA records:", err)
	}

	os.Exit(0)
}

func getTLSARecords() ([]tlsaRecord, error) {
	zoneID := os.Getenv("ZONE_ID")
	authToken := os.Getenv("API_TOKEN")
	domain := os.Getenv("DOMAIN")

	url := fmt.Sprintf("%s%s/dns_records?name=_%d._%s.%s", cloudflareAPI, zoneID, port, protocol, domain)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+authToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make HTTP request: %v", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println("Error closing HTTP body", err)
		}
	}(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed reading response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("recieved %d HTTP response status code for GET request, response body: %s", resp.StatusCode, string(body))
	}

	var response tlsaRecordsResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JSON response: %v", err)
	}

	return response.Result, nil
}

func generateCert(keyPath string) (string, error) {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return "", fmt.Errorf("failed to read key file: %v", err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block from key file")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %v", err)
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %v", err)
	}

	hash := sha256.New()
	hash.Write(publicKeyBytes)
	hashSum := hash.Sum(nil)

	return hex.EncodeToString(hashSum), nil
}

func deleteAll(tlsaRecords []tlsaRecord) error {
	zoneID, authToken := os.Getenv("ZONE_ID"), os.Getenv("API_TOKEN")

	for _, record := range tlsaRecords {
		log.Println("Deleting DNS record:", record.ID)
		url := cloudflareAPI + zoneID + "/dns_records/" + record.ID
		resp, err := makeHTTPRequest("DELETE", url, authToken, nil)
		err = handleResponse(resp, err, "DELETE")
		if err != nil {
			return err
		}
	}

	return nil
}

func addRequest(hash string) error {
	log.Println("Adding DNS record with hash:", hash)

	zoneID, authToken, domain := os.Getenv("ZONE_ID"), os.Getenv("API_TOKEN"), os.Getenv("DOMAIN")
	url := cloudflareAPI + zoneID + "/dns_records"

	payload := fmt.Sprintf(
		`{"type":"TLSA","name":"_%d._%s.%s","data":{"usage":%d,"selector":%d,"matching_type":%d,"certificate":"%s"}}`,
		port, protocol, domain, usage, selector, matchingType, hash)

	resp, err := makeHTTPRequest("POST", url, authToken, []byte(payload))
	return handleResponse(resp, err, "POST")
}

func modifyRequest(hash, id string) error {
	log.Println("Modifying DNS record:", id, "with hash:", hash)

	zoneID, authToken, domain := os.Getenv("ZONE_ID"), os.Getenv("API_TOKEN"), os.Getenv("DOMAIN")
	url := cloudflareAPI + zoneID + "/dns_records/" + id

	payload := fmt.Sprintf(
		`{"type":"TLSA","name":"_%d._%s.%s","data":{"usage":%d,"selector":%d,"matching_type":%d,"certificate":"%s"}}`,
		port, protocol, domain, usage, selector, matchingType, hash)

	resp, err := makeHTTPRequest("PUT", url, authToken, []byte(payload))
	return handleResponse(resp, err, "PUT")
}

func makeHTTPRequest(method, url, authToken string, payload []byte) (*http.Response, error) {
	req, err := http.NewRequest(method, url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	return client.Do(req)
}

func handleResponse(resp *http.Response, err error, action string) error {
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println("Error closing HTTP body:", err)
		}
	}(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed reading response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("recieved %d HTTP response status code for %s request, response body: %s", resp.StatusCode, action, string(body))
	}

	return nil
}

func checkData(record tlsaRecord, hash string) (correct bool) {
	return record.Data.Usage == usage &&
		record.Data.Selector == selector &&
		record.Data.MatchingType == matchingType &&
		record.Data.Certificate == hash
}
