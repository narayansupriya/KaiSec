package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type MockVulnerabilityStore struct {
	mock.Mock
}

// Mock the storeVulnerability function
func (m *MockVulnerabilityStore) storeVulnerability(vulnerability Vulnerability) error {
	args := m.Called(vulnerability)
	return args.Error(0)
}

type MockDB struct {
	mock.Mock
}

func (m *MockDB) Query(query string, args ...interface{}) (RowScanner, error) {
	args = append([]interface{}{query}, args...)
	returnValues := m.Called(args...)
	return returnValues.Get(0).(RowScanner), returnValues.Error(1)
}

type MockRows struct {
	mock.Mock
}

func (r *MockRows) Next() bool {
	args := r.Called()
	return args.Bool(0)
}

func (r *MockRows) Scan(dest ...interface{}) error {
	args := r.Called(dest)
	return args.Error(0)
}

func (r *MockRows) Close() error {
	args := r.Called()
	return args.Error(0)
}

// createRequestWithBody is a helper function that creates an HTTP request with a given body
func createRequestWithBody(t *testing.T, reqBody string) (*http.Request, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Return the request and response recorder
	return req, w
}

func TestScanHandlerRequestBodies(t *testing.T) {
	// Define test cases
	tests := []struct {
		name            string
		reqBody         string
		expectedStatus  int
		expectedMessage string
	}{
		{
			name:            "Missing 'repo' field",
			reqBody:         `{"files": ["file1.go"]}`,
			expectedStatus:  http.StatusBadRequest,
			expectedMessage: "Missing or invalid 'repo' field",
		},
		{
			name:            "Empty 'files' field",
			reqBody:         `{"repo": "test-repo", "files": []}`,
			expectedStatus:  http.StatusBadRequest,
			expectedMessage: "Missing or empty 'files' field",
		},
		{
			name:            "Empty body",
			reqBody:         `{}`,
			expectedStatus:  http.StatusBadRequest,
			expectedMessage: "Invalid request body",
		},
		{
			name:            "Missing comma in request",
			reqBody:         `{"repo": "test-repo" "files": []}`,
			expectedStatus:  http.StatusBadRequest,
			expectedMessage: "Invalid request body",
		},
		{
			name:            "Passing string in files instead or list in request",
			reqBody:         `{"repo": "test-repo", "files": ""}`,
			expectedStatus:  http.StatusBadRequest,
			expectedMessage: "Missing or invalid 'repo' or 'files' field",
		},
		{
			name:            "Passing string in files instead or list in request",
			reqBody:         `{"repo": "test-repo", "files": []}`,
			expectedStatus:  http.StatusBadRequest,
			expectedMessage: "Missing or invalid 'repo' or 'files' field",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, w := createRequestWithBody(t, tt.reqBody)

			// Call the scan handler
			scanHandler(w, req)

			// Get the response
			res := w.Result()
			defer res.Body.Close()

			// Read and log the response body
			body, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("Failed to read response body: %v", err)
			}
			t.Logf("Response body: %s", body)

			// Check the response status code
			if res.StatusCode != http.StatusBadRequest {
				t.Errorf("Expected status 400, got %d", res.StatusCode)
			}
		})
	}
}

// Mocking the fetchWithRetry function
func TestScanHandler(t *testing.T) {
	// Ensure scanData is initialized
	scanData = []ScanResult{}

	// Setup mock fetchWithRetry function
	originalFetchWithRetry := fetchWithRetryFunc
	defer func() { fetchWithRetryFunc = originalFetchWithRetry }() // Restore after test

	// Variables for tracking concurrency
	var concurrentProcesses int32
	var maxConcurrent int32

	// Mocking the fetchWithRetry function for the test
	fetchWithRetryFunc = func(url string, attempts int) (*http.Response, error) {
		if strings.HasPrefix(url, "https://raw.githubusercontent.com/test-repo/main/") {
			// Increment the counter for active concurrent processes
			current := atomic.AddInt32(&concurrentProcesses, 1)
			if current > atomic.LoadInt32(&maxConcurrent) {
				atomic.StoreInt32(&maxConcurrent, current)
			}
			//introducing delay
			time.Sleep(100 * time.Millisecond)

			mockResponse := `[
			{
				"scanResults": {
				"scan_id": "scan_123456789",
					"vulnerabilities": [{
						"id": "CVE-2024-1234",
						"severity": "HIGH",
						"cvss": 8.5,
						"status": "fixed",
						"package_name": "openssl",
						"current_version": "1.1.1t-r0",
						"fixed_version": "1.1.1u-r0",
						"description": "Buffer overflow vulnerability in OpenSSL",
						"published_date": "2024-01-15T00:00:00Z",
						"link": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
					}]
				}
			}]`
			// Decrement counter when done
			defer atomic.AddInt32(&concurrentProcesses, -1)

			// Return the mock response
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(mockResponse)),
			}, nil
		}
		return nil, fmt.Errorf("unexpected URL: %s", url)
	}

	// Prepare request body
	reqBody := `{
        "repo": "test-repo",
        "filename": ["test-file.json", "test-file1.json", "test-file8.json", "test-file10.json"]
    }`

	req := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Create a mock instance
	mockStore := new(MockVulnerabilityStore)
	mockStore.On("storeVulnerability", mock.Anything).Return(nil) // Expecting the function call

	originalStoreVulnerability := funcStoreVulnerability
	defer func() { funcStoreVulnerability = originalStoreVulnerability }() // Restore after test

	funcStoreVulnerability = func(v Vulnerability) {
		mockStore.storeVulnerability(v) // Call mock function
	}

	// Call the scan handler
	scanHandler(w, req)

	// Get the response
	res := w.Result()
	defer res.Body.Close()

	// Read and log the response body
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}
	t.Logf("Response body: %s", body)

	// Check the response status code
	if res.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 OK, got %d", res.StatusCode)
	}

	// Parse the response body into a map to verify the message
	var response map[string]string
	err = json.Unmarshal(body, &response)
	if err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify that the response message is as expected
	expectedMessage := "Scan completed"
	if response["message"] != expectedMessage {
		t.Errorf("Expected response message: %s, got: %s", expectedMessage, response["message"])
	}

	current := atomic.LoadInt32(&maxConcurrent)
	if current != 4 {
		t.Errorf("Test failed: concurrent processes should be equal to number of files when less than the limit of %d, got %d", maxWorkers, current)
	}
}

func TestScanHandlerToCheckMaxConcurrentProcess(t *testing.T) {
	// Ensure scanData is initialized
	scanData = []ScanResult{}

	// Setup mock fetchWithRetry function
	originalFetchWithRetry := fetchWithRetryFunc
	defer func() { fetchWithRetryFunc = originalFetchWithRetry }() // Restore after test

	// Variables for tracking concurrency
	var concurrentProcesses int32
	var maxConcurrent int32

	// Mocking the fetchWithRetry function for the test
	fetchWithRetryFunc = func(url string, attempts int) (*http.Response, error) {
		if strings.HasPrefix(url, "https://raw.githubusercontent.com/test-repo/main/") {
			// Increment the counter for active concurrent processes
			current := atomic.AddInt32(&concurrentProcesses, 1)
			if current > atomic.LoadInt32(&maxConcurrent) {
				atomic.StoreInt32(&maxConcurrent, current)
			}
			time.Sleep(100 * time.Millisecond)

			mockResponse := `[
			{
				"scanResults": {
				"scan_id": "scan_123456789",
					"vulnerabilities": [{
						"id": "CVE-2024-1234",
						"severity": "HIGH",
						"cvss": 8.5,
						"status": "fixed",
						"package_name": "openssl",
						"current_version": "1.1.1t-r0",
						"fixed_version": "1.1.1u-r0",
						"description": "Buffer overflow vulnerability in OpenSSL",
						"published_date": "2024-01-15T00:00:00Z",
						"link": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
					}]
				}
			}]`
			// Decrement counter when done
			defer atomic.AddInt32(&concurrentProcesses, -1)

			// Return the mock response
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(mockResponse)),
			}, nil
		}
		return nil, fmt.Errorf("unexpected URL: %s", url)
	}

	// Prepare request body
	reqBody := `{
        "repo": "test-repo",
        "filename": ["test-file.json", "test-file1.json", "test-file8.json", "test-file10.json","test-file11.json", "test-file12.json", "test-file18.json", "test-file100.json", "test-file75.json", "test-file82.json", "test-file98.json", "test-file109.json"]
    }`

	req := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Create a mock instance
	mockStore := new(MockVulnerabilityStore)
	mockStore.On("storeVulnerability", mock.Anything).Return(nil) // Expecting the function call

	originalStoreVulnerability := funcStoreVulnerability
	defer func() { funcStoreVulnerability = originalStoreVulnerability }() // Restore after test

	funcStoreVulnerability = func(v Vulnerability) {
		mockStore.storeVulnerability(v) // Call mock function
	}

	// Call the scan handler
	scanHandler(w, req)

	// Get the response
	res := w.Result()
	defer res.Body.Close()

	// Read and log the response body
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}
	t.Logf("Response body: %s", body)

	// Check the response status code
	if res.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 OK, got %d", res.StatusCode)
	}

	// Parse the response body into a map to verify the message
	var response map[string]string
	err = json.Unmarshal(body, &response)
	if err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify that the response message is as expected
	expectedMessage := "Scan completed"
	if response["message"] != expectedMessage {
		t.Errorf("Expected response message: %s, got: %s", expectedMessage, response["message"])
	}

	current := atomic.LoadInt32(&maxConcurrent)
	if current <= 5 {
		t.Logf("Max concurrent processes observed: %d", atomic.LoadInt32(&maxConcurrent))
	}
	if current > maxWorkers {
		t.Errorf("Test failed: concurrent processes exceeded the limit of %d, got %d", maxWorkers, current)
	}
}

func TestStoreVulnerabilityMock(t *testing.T) {
	vuln := Vulnerability{
		ID:             "vuln-001",
		Severity:       "High",
		CVSS:           7.5,
		Status:         "Open",
		PackageName:    "example-package",
		CurrentVersion: "1.0.0",
		FixedVersion:   "1.1.0",
		Description:    "Sample vulnerability",
		PublishedDate:  "2025-02-01",
		Link:           "http://example.com/vuln-001",
		RiskFactors:    []string{"network", "unauthorized"},
		SourceFile:     "file1.go",
		ScanTime:       "2025-02-11T12:00:00Z",
	}

	// Replace the original storeVulnerability function with the mock for this test
	mockStore := new(MockVulnerabilityStore)

	// storeVulnerability should be called with 'vuln' and return nothing
	mockStore.On("storeVulnerability", vuln).Return(nil)

	mockStore.storeVulnerability(vuln)

	// Assertions
	mockStore.AssertExpectations(t)
}

func TestStoreVulnerabilityMockWithError(t *testing.T) {
	vuln := Vulnerability{
		//test data
	}

	// Replace the original storeVulnerability function with the mock for this test
	mockStore := new(MockVulnerabilityStore)

	// Mock storeVulnerability to return an error
	mockStore.On("storeVulnerability", vuln).Return(errors.New("database error")).Once()

	// Call the function under test, which should now trigger the error
	err := mockStore.storeVulnerability(vuln)

	// Assert that the error is not nil and contains the expected error message
	assert.NotNil(t, err, "Expected error but got nil")
	assert.Equal(t, "database error", err.Error(), "Error message does not match")

	// Assertions on the mock
	mockStore.AssertExpectations(t)
}

func TestQueryHandler_Success(t *testing.T) {
	mockDB := new(MockDB)
	rows := new(MockRows)

	// Mock Query execution
	mockDB.On("Query", "SELECT * FROM vulnerabilities WHERE severity = ?", "HIGH").
		Return(rows, nil)

	// Mock Next() and Scan() behavior for multiple rows
	rows.On("Next").Return(true).Once() // First row
	rows.On("Scan", mock.Anything).Return(nil).Once()

	rows.On("Next").Return(false).Once() // End of rows (Next will return false after processing the first row)

	// Mock Close() behavior
	rows.On("Close").Return(nil).Once()

	// Prepare request
	reqBody := `{
		"filters": {
			"severity": "high"
		}
	}`
	req := httptest.NewRequest(http.MethodPost, "/query", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Pass mockDB
	queryHandler(mockDB, w, req)

	// Read response
	res := w.Result()
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Errorf("Expected status 400, got %d", res.StatusCode)
	}

	body, _ := io.ReadAll(res.Body)

	// Check expected output
	expectedBody := `[]`
	if string(body) == expectedBody {
		t.Errorf("Expected body should not be empty '%s'", body)
	}

	// Verify mocks
	mockDB.AssertExpectations(t)
	rows.AssertExpectations(t)
}

func TestQueryHandler_Error(t *testing.T) {
	mockDB := new(MockDB)

	tests := []struct {
		name       string
		reqBody    string
		statusCode int
	}{
		{
			name:       "Invalid JSON Body",
			reqBody:    `{"filters": {severity: "high"}}`, // Invalid JSON (missing quotes around severity)
			statusCode: http.StatusBadRequest,
		},
		{
			name:       "Missing Filters Object",
			reqBody:    `{}`, // Missing filters object
			statusCode: http.StatusBadRequest,
		},
		{
			name:       "Missing Severity Field",
			reqBody:    `{"filters": {}}`, // Filters object is present, but no severity field
			statusCode: http.StatusBadRequest,
		},
		{
			name:       "Invalid Filters Type (Array instead of Object)",
			reqBody:    `{"filters": []}`, // filters is an array, but should be an object
			statusCode: http.StatusBadRequest,
		},
		{
			name:       "Invalid Severity Field (Non-string)",
			reqBody:    `{"filters": {"severity": 123}}`, // Severity is not a string
			statusCode: http.StatusBadRequest,
		},
		{
			name:       "Invalid Severity Field (Non-allowed)",
			reqBody:    `{"filters": {"severity": "NOT_HIGH"}}`, // Severity is not a string
			statusCode: http.StatusBadRequest,
		},
		{
			name:       "Missing Request Body",
			reqBody:    "", // Empty body
			statusCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Prepare the request with different invalid body
			req := httptest.NewRequest(http.MethodPost, "/query", bytes.NewBufferString(tt.reqBody))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			// Pass mockDB
			queryHandler(mockDB, w, req)

			// Read the response
			res := w.Result()
			defer res.Body.Close()

			if res.StatusCode != tt.statusCode {
				t.Errorf("Expected status %d, got %d", tt.statusCode, res.StatusCode)
			}
		})
	}
}
