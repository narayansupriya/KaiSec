# Kai Take-home Assessment
This project allows you to scan and query vulnerabilities based on their severity. 

It provides two main functionalities:
 - Scan API: Upload vulnerability data for processing.
 - Query API: Retrieve vulnerabilities from the database based on the severity.

# Running the Application
## 1a. Download the kai.tar file 
`docker load -i kai.tar`

## 1b. Running the Docker Container
You can run the container with the following command. The container will be available on port 8080:
`docker run -p 8080:8080 kai:latest`

## Use Step 1a and 1b or step 2a and 2b. (Preferred is step 1) continue from step 3.

## 2a. Building the Docker Image
To build the Docker image for the vulnerability scanner, run the following command:

`docker build -t kai:latest .`

## 2b. Running the Docker Container
You can run the container with the following command. The container will be available on port 8080:

`docker run -d -p 8080:8080 kai:latest`

If your container needs privileged access (for specific use cases), you can run it with elevated privileges using:

`docker run --privileged -d -p 8080:8080 kai:latest`

## 3. Accessing the Application
Once the container is running, the API will be accessible at `http://localhost:8080`

# API Endpoints
### 1. Scan API
This endpoint allows you to upload vulnerability scan data for processing.

Request Example
From postman

`curl --location 'http://localhost:8080/scan' \
--header 'Content-Type: application/json' \
--data '{
  "repo": "velancio/vulnerability_scans",
  "filename": ["vulnscan18.json", "vulscan123.json", "vulnscan1011.json", "vulnscan15.json", "vulnscan18.json"]
}'`

This request will trigger the scan process, uploading vulnerability scan data from the specified repository and filenames.

From windows command prompt :

`curl -X POST "http://localhost:8080/scan" -H "Content-Type: application/json" -d "{\"repo\": \"velancio/vulnerability_scans\", \"filename\": [\"vulnscan18.json\", \"vulscan123.json\", \"vulnscan1011.json\", \"vulnscan15.json\", \"vulnscan18.json\"]}"
`

### 2. Query API
This endpoint allows you to query vulnerabilities based on their severity.

Request Example
From postman

`curl --location 'http://localhost:8080/query' \
--header 'Content-Type: application/json' \
--data '{"filters": 
  {"severity": "CRITICAL"}
}'`

This query filters vulnerabilities based on the severity level, in this case, only retrieving CRITICAL vulnerabilities.
The allowed severity is "HIGH", "CRITICAL", "MEDIUM" and "LOW" - can be passed in lowercase as well.

From windows command prompt

`curl -X POST "http://localhost:8080/query" -H "Content-Type: application/json" -d "{\"filters\": {\"severity\": \"CRITICAL\"}}"
`

### example curl for testing negative scenario:
### *From Postman*
   #### a (Few files are not present)
   `curl --location 'http://localhost:8080/scan' \
   --header 'Content-Type: application/json' \
   --data '{
     "repo": "velancio/vulnerability_scans",
     "filename": ["vulnscan18.json", "vulsan123.json", "vlnscan1011.json", "vulnscan15.json", "vulnscan18.json"]
   }'`
   
   #### b (All files path is wrong, repo is wrong)
   `curl --location 'http://localhost:8080/scan' \
   --header 'Content-Type: application/json' \
   --data '{
     "repo": "velancio/vulnerability_scan",
     "filename": ["vulnscan18.json", "vulsan123.json", "vlnscan1011.json", "vulnscan15.json", "vulnscan18.json"]
   }'`
   
   #### c (everything is not right severity )
   `curl --location 'http://localhost:8080/query' \
   --header 'Content-Type: application/json' \
   --data '{"filters": 
   {"severity": "everything"}
   }'`
   
   #### d (severity is not in correct format)
   `curl --location 'http://localhost:8080/query' \
   --header 'Content-Type: application/json' \
   --data '{"filters": 
   ["severity": "CRITICAL"]
   }'`

### *From Windows Command Prompt*

   #### a (Few files are not present)
   `curl -X POST "http://localhost:8080/scan" -H "Content-Type: application/json" -d "{ \"repo\": \"velancio/vulnerability_scans\", \"filename\": [\"vulnscan18.json\", \"vulsan123.json\", \"vlnscan1011.json\", \"vulnscan15.json\", \"vulnscan18.json\"] }"
   `
   #### b (All files path is wrong, repo is wrong)
   
  `curl -X POST "http://localhost:8080/scan" -H "Content-Type: application/json" -d "{ \"repo\": \"velancio/vulnerability_scan\", \"filename\": [\"vulnscan18.json\", \"vulsan123.json\", \"vlnscan1011.json\", \"vulnscan15.json\", \"vulnscan18.json\"] }"
   `
   #### c (everything is not right severity )
   `curl -X POST "http://localhost:8080/query" -H "Content-Type: application/json" -d "{ \"filters\": { \"severity\": \"everything\" } }"
   `
   #### d (severity is not in correct format)
   `curl -X POST "http://localhost:8080/query" -H "Content-Type: application/json" -d "{ \"filters\": [ \"severity\": \"CRITICAL\" ] }"
   `

# **Notes**
Make sure to have Docker installed on your system to use image/build and run the container.
You can test the APIs using tools like Postman. Please ensure the Method is POST and the body is JSON type if not auto-imported by pasting curl.
Please make sure to use the right command , based on where you are running from.
The API is accessible on port 8080 by default. If you want to change the port, update the Docker run command accordingly.





