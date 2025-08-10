package vtclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	BaseURL     = "https://www.virustotal.com/api/v3"
	MaxFileSize = 32 * 1024 * 1024 // 32MB
)

type Client struct {
	APIKey     string
	HTTPClient *http.Client
	RateLimit  time.Duration
}

type ScanResult struct {
	ID         string                 `json:"id,omitempty"`
	Type       string                 `json:"type"`
	Attributes map[string]interface{} `json:"attributes"`
	Permalink  string                 `json:"permalink,omitempty"`
	Malicious  int                    `json:"malicious"`
	Suspicious int                    `json:"suspicious"`
	Undetected int                    `json:"undetected"`
	Harmless   int                    `json:"harmless"`
	Timeout    int                    `json:"timeout"`
	TotalScans int                    `json:"total_scans"`
	ScanDate   time.Time              `json:"scan_date"`
	EngineData []EngineResult         `json:"engines,omitempty"`
}

type EngineResult struct {
	Engine   string `json:"engine"`
	Category string `json:"category"`
	Result   string `json:"result"`
	Version  string `json:"version"`
	Update   string `json:"update"`
}

type FileAnalysis struct {
	Data struct {
		ID         string `json:"id"`
		Type       string `json:"type"`
		Attributes struct {
			Date         int                    `json:"date"`
			Status       string                 `json:"status"`
			Stats        map[string]int         `json:"stats"`
			Results      map[string]interface{} `json:"results"`
			Permalink    string                 `json:"permalink"`
			SHA256       string                 `json:"sha256"`
			SHA1         string                 `json:"sha1"`
			MD5          string                 `json:"md5"`
			SSDEEP       string                 `json:"ssdeep"`
			TLSH         string                 `json:"tlsh"`
			Authentihash string                 `json:"authentihash"`
			Imphash      string                 `json:"imphash"`
			Names        []string               `json:"names"`
			Size         int                    `json:"size"`
			Type         string                 `json:"type_description"`
			MimeType     string                 `json:"mime_type"`
		} `json:"attributes"`
	} `json:"data"`
}

type URLAnalysis struct {
	Data struct {
		ID         string `json:"id"`
		Type       string `json:"type"`
		Attributes struct {
			Date             int                    `json:"date"`
			Stats            map[string]int         `json:"stats"`
			Results          map[string]interface{} `json:"results"`
			URL              string                 `json:"url"`
			LastAnalysisDate int                    `json:"last_analysis_date"`
		} `json:"attributes"`
	} `json:"data"`
}

type IPAnalysis struct {
	Data struct {
		ID         string `json:"id"`
		Type       string `json:"type"`
		Attributes struct {
			Network             string                 `json:"network"`
			Country             string                 `json:"country"`
			ASN                 int                    `json:"asn"`
			ASOwner             string                 `json:"as_owner"`
			LastAnalysisStats   map[string]int         `json:"last_analysis_stats"`
			LastAnalysisResults map[string]interface{} `json:"last_analysis_results"`
		} `json:"attributes"`
	} `json:"data"`
}

type DomainAnalysis struct {
	Data struct {
		ID         string `json:"id"`
		Type       string `json:"type"`
		Attributes struct {
			Categories          map[string]string      `json:"categories"`
			LastDNSRecords      []interface{}          `json:"last_dns_records"`
			LastAnalysisStats   map[string]int         `json:"last_analysis_stats"`
			LastAnalysisResults map[string]interface{} `json:"last_analysis_results"`
			Reputation          int                    `json:"reputation"`
			Whois               string                 `json:"whois"`
		} `json:"attributes"`
	} `json:"data"`
}

func NewClient(apiKey string) *Client {
	return &Client{
		APIKey: apiKey,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		RateLimit: time.Second / 4, // 4 requests per second for free tier
	}
}

func (c *Client) SetRateLimit(requestsPerSecond int) {
	if requestsPerSecond > 0 {
		c.RateLimit = time.Second / time.Duration(requestsPerSecond)
	}
}

func (c *Client) ScanFile(ctx context.Context, filePath string) (*ScanResult, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get file stats: %w", err)
	}

	if stat.Size() > MaxFileSize {
		return nil, fmt.Errorf("file too large: %d bytes (max: %d)", stat.Size(), MaxFileSize)
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		return nil, fmt.Errorf("failed to create form file: %w", err)
	}

	if _, err = io.Copy(part, file); err != nil {
		return nil, fmt.Errorf("failed to copy file data: %w", err)
	}

	writer.Close()

	req, err := http.NewRequestWithContext(ctx, "POST", BaseURL+"/files", &body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("X-Apikey", c.APIKey)

	time.Sleep(c.RateLimit)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Wait and get analysis results
	time.Sleep(15 * time.Second) // Wait for analysis to complete
	return c.GetFileAnalysis(ctx, result.Data.ID)
}

// GetHashAnalysis gets analysis for a hash (SHA256, SHA1, MD5)
func (c *Client) GetHashAnalysis(ctx context.Context, hash string) (*ScanResult, error) {
	url := fmt.Sprintf("%s/files/%s", BaseURL, hash)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Apikey", c.APIKey)

	time.Sleep(c.RateLimit)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return &ScanResult{
			ID:         hash,
			Type:       "file",
			Attributes: map[string]interface{}{"status": "not_found"},
		}, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	var analysis FileAnalysis
	if err := json.NewDecoder(resp.Body).Decode(&analysis); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return convertFileAnalysis(&analysis), nil
}

// GetFileAnalysis gets file analysis by analysis ID
func (c *Client) GetFileAnalysis(ctx context.Context, analysisID string) (*ScanResult, error) {
	url := fmt.Sprintf("%s/analyses/%s", BaseURL, analysisID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Apikey", c.APIKey)

	time.Sleep(c.RateLimit)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	var analysis FileAnalysis
	if err := json.NewDecoder(resp.Body).Decode(&analysis); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return convertFileAnalysis(&analysis), nil
}

// ScanURL scans a URL
func (c *Client) ScanURL(ctx context.Context, url string) (*ScanResult, error) {
	data := fmt.Sprintf("url=%s", url)

	req, err := http.NewRequestWithContext(ctx, "POST", BaseURL+"/urls",
		strings.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Apikey", c.APIKey)

	time.Sleep(c.RateLimit)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Wait and get analysis results
	time.Sleep(10 * time.Second)
	return c.GetURLAnalysis(ctx, result.Data.ID)
}

// GetURLAnalysis gets URL analysis by ID or URL
func (c *Client) GetURLAnalysis(ctx context.Context, identifier string) (*ScanResult, error) {
	// If identifier looks like analysis ID, use analyses endpoint
	var url string
	if strings.Contains(identifier, "-") {
		url = fmt.Sprintf("%s/analyses/%s", BaseURL, identifier)
	} else {
		// Assume it's a URL, encode it
		url = fmt.Sprintf("%s/urls/%s", BaseURL, identifier)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Apikey", c.APIKey)

	time.Sleep(c.RateLimit)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	var analysis URLAnalysis
	if err := json.NewDecoder(resp.Body).Decode(&analysis); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return convertURLAnalysis(&analysis), nil
}

// GetIPAnalysis gets IP address analysis
func (c *Client) GetIPAnalysis(ctx context.Context, ip string) (*ScanResult, error) {
	url := fmt.Sprintf("%s/ip_addresses/%s", BaseURL, ip)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Apikey", c.APIKey)

	time.Sleep(c.RateLimit)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	var analysis IPAnalysis
	if err := json.NewDecoder(resp.Body).Decode(&analysis); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return convertIPAnalysis(&analysis), nil
}

// GetDomainAnalysis gets domain analysis
func (c *Client) GetDomainAnalysis(ctx context.Context, domain string) (*ScanResult, error) {
	url := fmt.Sprintf("%s/domains/%s", BaseURL, domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Apikey", c.APIKey)

	time.Sleep(c.RateLimit)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	var analysis DomainAnalysis
	if err := json.NewDecoder(resp.Body).Decode(&analysis); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return convertDomainAnalysis(&analysis), nil
}

// Helper functions to convert API responses to unified ScanResult

func convertFileAnalysis(analysis *FileAnalysis) *ScanResult {
	result := &ScanResult{
		ID:         analysis.Data.ID,
		Type:       "file",
		Attributes: make(map[string]interface{}),
		ScanDate:   time.Unix(int64(analysis.Data.Attributes.Date), 0),
	}

	if analysis.Data.Attributes.Stats != nil {
		result.Malicious = analysis.Data.Attributes.Stats["malicious"]
		result.Suspicious = analysis.Data.Attributes.Stats["suspicious"]
		result.Undetected = analysis.Data.Attributes.Stats["undetected"]
		result.Harmless = analysis.Data.Attributes.Stats["harmless"]
		result.Timeout = analysis.Data.Attributes.Stats["timeout"]
		result.TotalScans = result.Malicious + result.Suspicious + result.Undetected + result.Harmless + result.Timeout
	}

	result.Attributes["sha256"] = analysis.Data.Attributes.SHA256
	result.Attributes["sha1"] = analysis.Data.Attributes.SHA1
	result.Attributes["md5"] = analysis.Data.Attributes.MD5
	result.Attributes["size"] = analysis.Data.Attributes.Size
	result.Attributes["type"] = analysis.Data.Attributes.Type
	result.Attributes["names"] = analysis.Data.Attributes.Names
	result.Permalink = analysis.Data.Attributes.Permalink

	return result
}

func convertURLAnalysis(analysis *URLAnalysis) *ScanResult {
	result := &ScanResult{
		ID:         analysis.Data.ID,
		Type:       "url",
		Attributes: make(map[string]interface{}),
		ScanDate:   time.Unix(int64(analysis.Data.Attributes.Date), 0),
	}

	if analysis.Data.Attributes.Stats != nil {
		result.Malicious = analysis.Data.Attributes.Stats["malicious"]
		result.Suspicious = analysis.Data.Attributes.Stats["suspicious"]
		result.Undetected = analysis.Data.Attributes.Stats["undetected"]
		result.Harmless = analysis.Data.Attributes.Stats["harmless"]
		result.Timeout = analysis.Data.Attributes.Stats["timeout"]
		result.TotalScans = result.Malicious + result.Suspicious + result.Undetected + result.Harmless + result.Timeout
	}

	result.Attributes["url"] = analysis.Data.Attributes.URL

	return result
}

func convertIPAnalysis(analysis *IPAnalysis) *ScanResult {
	result := &ScanResult{
		ID:         analysis.Data.ID,
		Type:       "ip",
		Attributes: make(map[string]interface{}),
	}

	if analysis.Data.Attributes.LastAnalysisStats != nil {
		result.Malicious = analysis.Data.Attributes.LastAnalysisStats["malicious"]
		result.Suspicious = analysis.Data.Attributes.LastAnalysisStats["suspicious"]
		result.Undetected = analysis.Data.Attributes.LastAnalysisStats["undetected"]
		result.Harmless = analysis.Data.Attributes.LastAnalysisStats["harmless"]
		result.Timeout = analysis.Data.Attributes.LastAnalysisStats["timeout"]
		result.TotalScans = result.Malicious + result.Suspicious + result.Undetected + result.Harmless + result.Timeout
	}

	result.Attributes["network"] = analysis.Data.Attributes.Network
	result.Attributes["country"] = analysis.Data.Attributes.Country
	result.Attributes["asn"] = analysis.Data.Attributes.ASN
	result.Attributes["as_owner"] = analysis.Data.Attributes.ASOwner

	return result
}

func convertDomainAnalysis(analysis *DomainAnalysis) *ScanResult {
	result := &ScanResult{
		ID:         analysis.Data.ID,
		Type:       "domain",
		Attributes: make(map[string]interface{}),
	}

	if analysis.Data.Attributes.LastAnalysisStats != nil {
		result.Malicious = analysis.Data.Attributes.LastAnalysisStats["malicious"]
		result.Suspicious = analysis.Data.Attributes.LastAnalysisStats["suspicious"]
		result.Undetected = analysis.Data.Attributes.LastAnalysisStats["undetected"]
		result.Harmless = analysis.Data.Attributes.LastAnalysisStats["harmless"]
		result.Timeout = analysis.Data.Attributes.LastAnalysisStats["timeout"]
		result.TotalScans = result.Malicious + result.Suspicious + result.Undetected + result.Harmless + result.Timeout
	}

	result.Attributes["reputation"] = analysis.Data.Attributes.Reputation
	result.Attributes["categories"] = analysis.Data.Attributes.Categories

	return result
}
