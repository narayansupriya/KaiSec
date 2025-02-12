package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

const maxWorkers = 5 // Limit to 5 concurrent workers
var fetchWithRetryFunc = fetchWithRetry

var funcStoreVulnerability = storeVulnerability

var scanData []ScanResult

var db *sql.DB

type QueryExecutor interface {
	Query(query string, args ...interface{}) (RowScanner, error)
}

type RowScanner interface {
	Next() bool
	Scan(dest ...interface{}) error
	Close() error
}

type DBWrapper struct {
	*sql.DB
}

// Implement Query method for DBWrapper to satisfy QueryExecutor interface
func (db *DBWrapper) Query(query string, args ...interface{}) (RowScanner, error) {
	rows, err := db.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	return rows, nil
}

type ScanResult struct {
	ScanResults struct {
		ScanID          string          `json:"scan_id"`
		Timestamp       string          `json:"timestamp"`
		ScanStatus      string          `json:"scan_status"`
		ResourceType    string          `json:"resource_type"`
		ResourceName    string          `json:"resource_name"`
		Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	} `json:"scanResults"`
}

// single vulnerability entry
type Vulnerability struct {
	ID             string   `json:"id"`
	Severity       string   `json:"severity"`
	CVSS           float64  `json:"cvss"`
	Status         string   `json:"status"`
	PackageName    string   `json:"package_name"`
	CurrentVersion string   `json:"current_version"`
	FixedVersion   string   `json:"fixed_version"`
	Description    string   `json:"description"`
	PublishedDate  string   `json:"published_date"`
	Link           string   `json:"link"`
	RiskFactors    []string `json:"risk_factors"`
	SourceFile     string   `json:"source_file"`
	ScanTime       string   `json:"scan_time"`
}

func main() {
	var err error
	db, err = sql.Open("sqlite3", "./vulns.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	dbWrapper := &DBWrapper{db}

	createTable()

	http.HandleFunc("/scan", scanHandler)
	http.HandleFunc("/query", func(w http.ResponseWriter, r *http.Request) {
		queryHandler(dbWrapper, w, r)
	})

	log.Println("Server running on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func createTable() {
	query := `CREATE TABLE IF NOT EXISTS vulnerabilities (
		id TEXT NOT NULL PRIMARY KEY,
		severity TEXT NOT NULL,
		cvss REAL,
		status TEXT,
		package_name TEXT,
		current_version TEXT,
		fixed_version TEXT,
		description TEXT,
		published_date TEXT,
		link TEXT,
		risk_factors TEXT,
		source_file TEXT,
		scan_time TEXT
	)`

	_, err := db.Exec(query)
	if err != nil {
		log.Fatal(err)
	}
	// Create an index on the severity column
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_severity ON vulnerabilities(severity);`)
	if err != nil {
		log.Fatal(err)
	}
}

func scanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		Repo  string   `json:"repo"`
		Files []string `json:"filename"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	// Check if the request fields are valid
	if request.Repo == "" || len(request.Files) == 0 {
		http.Error(w, "Missing or invalid 'repo' or 'files' field", http.StatusBadRequest)
		return
	}

	// Create a set to store unique filenames
	fileSet := make(map[string]struct{})
	for _, file := range request.Files {
		fileSet[file] = struct{}{} // Adding file to set (duplicates will be ignored)
	}

	// Convert the set back to a slice
	uniqueFiles := make([]string, 0, len(fileSet))
	for file := range fileSet {
		uniqueFiles = append(uniqueFiles, file)
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(uniqueFiles))
	sem := make(chan struct{}, maxWorkers) // Semaphore to limit the number of concurrent workers

	for _, file := range uniqueFiles {
		wg.Add(1)
		sem <- struct{}{} // Acquire a slot
		go func(f string) {
			defer wg.Done()
			defer func() { <-sem }() // Release the slot
			if err := processFile(request.Repo, f); err != nil {
				errChan <- err
			}
		}(file)
	}

	wg.Wait()
	close(errChan)

	if len(errChan) > 0 {
		http.Error(w, "Some files failed to process", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Scan completed"})
}

func processFile(repo, file string) error {
	url := fmt.Sprintf("https://raw.githubusercontent.com/%s/main/%s", repo, file)
	fmt.Println("Fetching:", url)
	resp, err := fetchWithRetryFunc(url, 2)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var scanData []struct {
		ScanResults struct {
			Vulnerabilities []Vulnerability `json:"vulnerabilities"`
		} `json:"scanResults"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&scanData); err != nil {
		return err
	}

	vulnCount := 0 // Counter for vulnerabilities

	for _, scan := range scanData {
		scanTime := time.Now().Format(time.RFC3339)
		if scan.ScanResults.Vulnerabilities != nil {
			for _, v := range scan.ScanResults.Vulnerabilities {
				v.SourceFile = file
				v.ScanTime = scanTime
				funcStoreVulnerability(v)
				vulnCount++ // Increment vulnerability count
			}
		} else {
			log.Printf("No vulnerabilities found in scan for file: %s", file)
		}
	}

	log.Printf("Total vulnerabilities found and added for file %s: %d", file, vulnCount)
	return nil
}

func fetchWithRetry(url string, attempts int) (*http.Response, error) {
	var err error
	for i := 0; i < attempts; i++ {
		resp, err := http.Get(url)
		if err == nil {
			if resp.StatusCode == http.StatusOK {
				return resp, nil
			}
			// Handle non-OK status codes (e.g., 404, 500)
			resp.Body.Close()
			return nil, fmt.Errorf("failed to fetch file from %s, status code: %d", url, resp.StatusCode)
		}
		// Retry if there is a network error
		time.Sleep(2 * time.Second)
	}
	return nil, fmt.Errorf("failed to fetch file from %s after %d attempts: %w", url, attempts, err)
}

func storeVulnerability(v Vulnerability) {
	//Using Insert or replace to make sure if a file is rescanned and there is any update in existing vuln, its updated in our db.
	_, err := db.Exec(
		`INSERT OR REPLACE INTO vulnerabilities (id, severity, cvss, status, package_name, current_version, fixed_version, description, published_date, link, risk_factors, source_file, scan_time)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		v.ID, v.Severity, v.CVSS, v.Status, v.PackageName, v.CurrentVersion, v.FixedVersion, v.Description, v.PublishedDate, v.Link, fmt.Sprintf("%v", v.RiskFactors), v.SourceFile, v.ScanTime,
	)
	if err != nil {
		log.Printf("Error storing vulnerability: %v", err)
	}
}

func queryHandler(db QueryExecutor, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		Filters struct {
			Severity string `json:"severity"`
		} `json:"filters"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Ensure "filters" is a valid object and contains the "severity" field
	if request.Filters.Severity == "" {
		http.Error(w, "Missing or invalid severity field", http.StatusBadRequest)
		return
	}

	// Convert severity to uppercase
	request.Filters.Severity = strings.ToUpper(request.Filters.Severity)

	// Validate the severity field
	validSeverities := map[string]bool{
		"HIGH":     true,
		"CRITICAL": true,
		"LOW":      true,
		"MEDIUM":   true,
	}

	if !validSeverities[request.Filters.Severity] {
		http.Error(w, "Invalid severity value please use allowed - 'HIGH','MEDIUM','CRITICAL' or 'LOW'", http.StatusBadRequest)
		return
	}

	rows, err := db.Query("SELECT * FROM vulnerabilities WHERE severity = ?", request.Filters.Severity)
	if err != nil {
		http.Error(w, "Database query error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var results []Vulnerability
	for rows.Next() {
		var v Vulnerability
		var riskFactors string
		rows.Scan(&v.ID, &v.Severity, &v.CVSS, &v.Status, &v.PackageName, &v.CurrentVersion, &v.FixedVersion, &v.Description, &v.PublishedDate, &v.Link, &riskFactors, &v.SourceFile, &v.ScanTime)
		json.Unmarshal([]byte(riskFactors), &v.RiskFactors)
		results = append(results, v)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}
