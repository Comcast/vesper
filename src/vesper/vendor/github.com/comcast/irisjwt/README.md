# irisjwt

irisjwt is a Go package for basic validation of JWTs. At this point, it does the following

- signature verification based on public keys
- validate expiration time in JWT claims
- caches public keys based on "app_key" value in JWT claims
- provides a function to clear a cached public key based on "app_key" value
- provides a convenience function to retrieve scopes from JWT claims
- provides a convenience function to fetch bearer JWT from AUM given key and secret

*Note: At this point, this package caters to retrieval of public keys from only one X.509 URL (CNAME/FQDN)*

## Installation

```sh
go get github.com/comcast/irisjwt
```

## Initialization

Applications *MUST* set the X.509 URL at startup

**Example**
 
```sh
package main

import "github.com/comcast/irisjwt"

func init() {
	// Initialize X.509 URL from where the public KEYS can be retrieved
	irisjwt.SetX5u(https://<CNAME/FQDN>/jwtkeys)
}

.......
```

## Clear Cache

**Example**
 
```sh
package main

import "github.com/comcast/irisjwt"

// clear cached public key
irisjwt.ClearCache(<jwt_claims_app_key>)

.......
```

## Retrieve Scopes

**Example**
 
```sh
package main

import "github.com/comcast/irisjwt"

// retrieve scopes from JWT
var scopes string
scopes = irisjwt.Scopes(<JWT token>)

.......
```

## Fetch Bearer JWT
import "github.com/comcast/irisjwt"

// retrieve scopes from JWT
e, t, err = irisjwt.GetServerJwt(<AUM url>, <key>, <secret>)


## TBD

- Make this package more generic in implementation
- Add other ways to validate signature (certificate, shared key....)
