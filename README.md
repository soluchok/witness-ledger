# Verifiable Credential Transparency (VCT)
## Prerequisites (for running tests and demos)
- Go 1.16
- Docker
- Docker-Compose
- Make
- bash

## How to run the service?

1. Run all dependencies (mysql, trillian log and signer services)
```bash
cd deployments && docker-compose up
```

2. Go to root directory and executte.
```bash
make witness-ledger-demo
```

## Rest API

### add-chain
Request

```curl
curl --location --request POST 'http://localhost:7777/ct/v1/add-chain' --data-raw '{"key":"val"}'
```

Response

```json
{
   "sct_version":0,
   "id":null,
   "timestamp":1616164936082,
   "extensions":"",
   "signature":null
}
```

### get-sth
Request

```curl
curl --location --request GET 'http://localhost:7777/ct/v1/get-sth'
```

Response

```json
{
   "tree_size":4,
   "timestamp":1616164936161,
   "sha256_root_hash":"c2ZFUOJiAnzXXweQl7GJGCP/Y5TT2DHldgQAtBYPcts=",
   "tree_head_signature":null
}
```

### get-entries
Request

```curl
curl --location --request GET 'http://localhost:7777/ct/v1/get-entries?start=0&end=10'
```

Response

```json
{
   "entries":[
      {
         "leaf_input":"eyJWZXJzaW9uIjowLCJMZWFmVHlwZSI6MCwiVGltZXN0YW1wZWRFbnRyeSI6eyJUaW1lc3RhbXAiOjE2MTYxNjQ4MDIwNjcsIkVudHJ5VHlwZSI6MCwiVkNFbnRyeSI6IllXRmhZV1JtWkdaa2MyUnoiLCJFeHRlbnNpb25zIjpudWxsfX0=",
         "extra_data":null
      },
      {
         "leaf_input":"eyJWZXJzaW9uIjowLCJMZWFmVHlwZSI6MCwiVGltZXN0YW1wZWRFbnRyeSI6eyJUaW1lc3RhbXAiOjE2MTYxNjQ4MDY3NjYsIkVudHJ5VHlwZSI6MCwiVkNFbnRyeSI6IllXRmhZV1JtWkdaa2N3PT0iLCJFeHRlbnNpb25zIjpudWxsfX0=",
         "extra_data":null
      },
      {
         "leaf_input":"eyJWZXJzaW9uIjowLCJMZWFmVHlwZSI6MCwiVGltZXN0YW1wZWRFbnRyeSI6eyJUaW1lc3RhbXAiOjE2MTYxNjQ4MDgwNjksIkVudHJ5VHlwZSI6MCwiVkNFbnRyeSI6IllXRmhZV1JtWkdZPSIsIkV4dGVuc2lvbnMiOm51bGx9fQ==",
         "extra_data":null
      },
      {
         "leaf_input":"eyJWZXJzaW9uIjowLCJMZWFmVHlwZSI6MCwiVGltZXN0YW1wZWRFbnRyeSI6eyJUaW1lc3RhbXAiOjE2MTYxNjQ5MzYwODIsIkVudHJ5VHlwZSI6MCwiVkNFbnRyeSI6ImV5SnJaWGtpT2lKMllXd2lmUT09IiwiRXh0ZW5zaW9ucyI6bnVsbH19",
         "extra_data":null
      }
   ]
}
```

### get-proof-by-hash
#### How to get hash?
```go
package main

import (
	"encoding/base64"
	"fmt"

	"github.com/google/trillian/merkle/rfc6962"
)

func main() {
	leaf := "eyJWZXJzaW9uIjowLCJMZWFmVHlwZSI6MCwiVGltZXN0YW1wZWRFbnRyeSI6eyJUaW1lc3RhbXAiOjE2MTYxNjQ4MDgwNjksIkVudHJ5VHlwZSI6MCwiVkNFbnRyeSI6IllXRmhZV1JtWkdZPSIsIkV4dGVuc2lvbnMiOm51bGx9fQ=="
	leafData, _ := base64.StdEncoding.DecodeString(leaf)
	fmt.Println(base64.StdEncoding.EncodeToString(rfc6962.DefaultHasher.HashLeaf(leafData)))

    // Output:
    // +clFEUPvJ+zUf9kcjINB2Q9ts6ubDcttZGTw/EAe2Hk=
}
```
NOTE: Do not forget to encode values to URL-encoded format
```
# before
+clFEUPvJ+zUf9kcjINB2Q9ts6ubDcttZGTw/EAe2Hk=
# after
%2BclFEUPvJ%2BzUf9kcjINB2Q9ts6ubDcttZGTw%2FEAe2Hk%3D
```

Request

```curl
curl --location --request GET 'http://localhost:7777/ct/v1/get-proof-by-hash?hash=%2BclFEUPvJ%2BzUf9kcjINB2Q9ts6ubDcttZGTw%2FEAe2Hk%3D&tree_size=4'
```

Response

```json
{
   "leaf_index":2,
   "audit_path":[
      "C0EqG5WpOyt+alw1knIoP+eUnkQpdc+IJ8H54jMJ8Io=",
      "YSdIhHuQwUlDDLggE5NrnWaKSJF4BilZpV1KgVmFMXE="
   ]
}
```