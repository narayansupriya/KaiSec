# KaiSec Take-home assessment
Scan and query for vulnerabilities based on their severity.

# To run the docker use the following
 docker build -t vulnerability-scanner .
 (or)
 docker run --privileged -d vulnerability-scanner

 On port 8080
 docker run -d -p 8080:8080 vulnerability-scanner

 # Run from the postman for scan API
 ```curl --location 'http://localhost:8080/scan' \
--header 'Content-Type: application/json' \
--data '{
  "repo": "velancio/vulnerability_scans",
  "filename": ["vulnscan18.json", "vulscan123.json", "vulnscan1011.json", "vulnscan15.json", "vulnscan18.json"]
}'```

# Run from the postman for query API
```curl --location 'http://localhost:8080/query' \
--header 'Content-Type: application/json' \
--data '{"filters": 
{"severity": "CRITICAL"}
}'```






