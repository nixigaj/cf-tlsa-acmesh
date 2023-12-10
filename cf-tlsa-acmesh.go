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
			log.Println("Error:", envVar, "environment variable is not defined")
			os.Exit(1)
		}
	}

	cert, err := generateCert(os.Getenv("KEY_FILE"))
	if err != nil {
		log.Println("Error generating cert:", err)
		os.Exit(1)
	}

	certNext, err := generateCert(os.Getenv("KEY_FILE_NEXT"))
	if err != nil {
		log.Println("Error generating next cert:", err)
		os.Exit(1)
	}

	log.Println("Current cert:", cert)
	log.Println("Next cert:", certNext)

	tlsaRecords, err := getTLSARecords()
	if err != nil {
		log.Println("Error:", err)
		return
	}

	for i, record := range tlsaRecords {
		log.Printf("DNS record %d: ID: %s, cert: %s\n", i+1, record.ID, record.Data.Certificate)
	}

	if len(tlsaRecords) != 2 {
		log.Println("Incorrect number of DNS entries. Deleting them and generating new ones.")
		deleteAll(tlsaRecords)
		addRequest(certNext)
		addRequest(cert)
		return
	}

	if (checkData(tlsaRecords[0], cert) && checkData(tlsaRecords[1], certNext)) ||
		(checkData(tlsaRecords[0], certNext) && checkData(tlsaRecords[1], cert)) {
		log.Println("Nothing to do!")
	} else if checkData(tlsaRecords[0], cert) {
		modifyRequest(certNext, tlsaRecords[1].ID)
	} else if checkData(tlsaRecords[0], certNext) {
		modifyRequest(cert, tlsaRecords[1].ID)
	} else if checkData(tlsaRecords[1], cert) {
		modifyRequest(certNext, tlsaRecords[0].ID)
	} else if checkData(tlsaRecords[1], certNext) {
		modifyRequest(cert, tlsaRecords[0].ID)
	} else {
		modifyRequest(certNext, tlsaRecords[1].ID)
		modifyRequest(cert, tlsaRecords[0].ID)
	}
}

func getTLSARecords() ([]tlsaRecord, error) {
	requiredEnvVars := []string{"ZONE_ID", "API_TOKEN", "DOMAIN"}
	for _, envVar := range requiredEnvVars {
		if os.Getenv(envVar) == "" {
			return nil, fmt.Errorf("%s environment variable is not defined", envVar)
		}
	}

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

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP request failed with status code: %s", resp.Status)
	}

	var response tlsaRecordsResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
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

func deleteAll(tlsaRecords []tlsaRecord) {
	zoneID, authToken := os.Getenv("ZONE_ID"), os.Getenv("API_TOKEN")

	for _, record := range tlsaRecords {
		log.Println("Deleting DNS record:", record.ID)
		url := cloudflareAPI + zoneID + "/dns_records/" + record.ID
		resp, err := makeHTTPRequest("DELETE", url, authToken, nil)
		handleResponse(resp, err, "DELETE")
	}
}

func addRequest(hash string) {
	log.Println("Adding DNS record with hash:", hash)

	zoneID, authToken, domain := os.Getenv("ZONE_ID"), os.Getenv("API_TOKEN"), os.Getenv("DOMAIN")
	url := cloudflareAPI + zoneID + "/dns_records"

	payload := fmt.Sprintf(
		`{"type":"TLSA","name":"_%d._%s.%s","data":{"usage":%d,"selector":%d,"matching_type":%d,"certificate":"%s"}}`,
		port, protocol, domain, usage, selector, matchingType, hash)

	resp, err := makeHTTPRequest("POST", url, authToken, []byte(payload))
	handleResponse(resp, err, "POST")
}

func modifyRequest(hash, id string) {
	log.Println("Modifying DNS record:", id, "with hash:", hash)

	zoneID, authToken, domain := os.Getenv("ZONE_ID"), os.Getenv("API_TOKEN"), os.Getenv("DOMAIN")
	url := cloudflareAPI + zoneID + "/dns_records/" + id

	payload := fmt.Sprintf(
		`{"type":"TLSA","name":"_%d._%s.%s","data":{"usage":%d,"selector":%d,"matching_type":%d,"certificate":"%s"}}`,
		port, protocol, domain, usage, selector, matchingType, hash)

	resp, err := makeHTTPRequest("PUT", url, authToken, []byte(payload))
	handleResponse(resp, err, "PUT")
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

func handleResponse(resp *http.Response, err error, action string) {
	if err != nil {
		log.Println("Error:", err)
		os.Exit(1)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println("Error closing HTTP body", err)
		}
	}(resp.Body)

	log.Println(action, "HTTP Status Code:", resp.Status)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Println("Error reading response body:", err)
		} else {
			log.Println("Response Body:", string(body))
		}
		os.Exit(1)
	}
}

func checkData(record tlsaRecord, hash string) (correct bool) {
	return record.Data.Usage == usage &&
		record.Data.Selector == selector &&
		record.Data.MatchingType == matchingType &&
		record.Data.Certificate == hash
}
