# KaiSec Take-home Assessment
This project allows you to scan and query vulnerabilities based on their severity. 

It provides two main functionalities:
 - Scan API: Upload vulnerability data for processing.
 - Query API: Retrieve vulnerabilities from the database based on the severity.

# Running the Application
## 1. Building the Docker Image
To build the Docker image for the vulnerability scanner, run the following command:

`docker build -t vulnerability-scanner .`

## 2. Running the Docker Container
You can run the container with the following command. The container will be available on port 8080:

`docker run -d -p 8080:8080 vulnerability-scanner`

If your container needs privileged access (for specific use cases), you can run it with elevated privileges using:

`docker run --privileged -d -p 8080:8080 vulnerability-scanner`

## 3. Accessing the Application
Once the container is running, the API will be accessible at `http://localhost:8080`

# API Endpoints
### 1. Scan API
This endpoint allows you to upload vulnerability scan data for processing.

cURL Request Example
`
curl --location 'http://localhost:8080/scan' \
--header 'Content-Type: application/json' \
--data '{
  "repo": "velancio/vulnerability_scans",
  "filename": ["vulnscan18.json", "vulscan123.json", "vulnscan1011.json", "vulnscan15.json", "vulnscan18.json"]
}'`
This request will trigger the scan process, uploading vulnerability scan data from the specified repository and filenames.

### 2. Query API
This endpoint allows you to query vulnerabilities based on their severity.

cURL Request Example
`
curl --location 'http://localhost:8080/query' \
--header 'Content-Type: application/json' \
--data '{"filters": 
  {"severity": "CRITICAL"}
}'`
This query filters vulnerabilities based on the severity level, in this case, only retrieving CRITICAL vulnerabilities.
The allowed severity is "HIGH", "CRITICAL", "MEDIUM" and "LOW" - can be passed in lowercase as well.

# **Notes**
*Make sure to have Docker installed on your system to build and run the container.
You can test the APIs using tools like Postman or directly with curl.
The API is accessible on port 8080 by default. If you want to change the port, update the Docker run command accordingly.*





