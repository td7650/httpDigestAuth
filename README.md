http-digest-auth-client
=======================

Go (golang) http digest authentication client.

###This fork includes the following changes:

- Changed MD5 hash generation to clean up some code
- Added proper closing of request bodies (urgently needed for many requests in a row)
- Removed fatal errors instead return with error (and log error text)
 
###Usage

```go
import (
    "net/http"
    httpDigestAuth "github.com/pteich/http-digest-auth-client"
)
 
var DigestAuth *httpDigestAuth.DigestHeaders
 
func main() {

    httpClient := http.Client{}

    DigestAuth = &httpDigestAuth.DigestHeaders{}
    DigestAuth, err = DigestAuth.Auth("user","pass","url")
	
    req, err := http.NewRequest("GET", "url", body)	
	
    DigestAuth.ApplyAuth(req)

    resp, err := httpClient.Do(req)
}
 
 ```
