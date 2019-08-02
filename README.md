# The Peculiar Authentication and User Management API

## Overview

ACME-client is a module that is designed to work with ACME servers and testing it.
This module is designed in accordance with the spec RFC8555.

## Instalation

```sh
npm i ACME-Client
```

## Usages
# To work with ACME server

```sh
import {AcmeClient} from "ACME-Client";

# Helper functions for easy operation
import {generateCSR, Convert} from "ACME-Client";

# Set options
const options: = {
  # Controller address of the directory of the ACME server
  url: string;
  # Domain for which you need to get a certificate
  domain: string;
  # A pair of crypto keys
  keys?: { privateKey, publicKey };
  # Specify the key signing algorithm
  algorithm: {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
      publicExponent: new Uint8Array([1, 0, 1]),
      modulusLength: 2048,
    };
  # Example mailto:example@gmail.com
  contact: string[];
  # Certificate validity period, default 1 year
  yearsValid?: number;
}

# Create keys if you don’t have them
const options.keys = await crypto.subtle.generateKey(options.algorithm, true, ["sign", "verify"]);

# Create a client
const client = new AcmeClient({authKey: options.keys.privateKey});

# Initialize a client
await client.initialize(options.url);

# Create account
const account = await client.createAccount({
    contact: options.contact,
    termsOfServiceAgreed: true,
  });

# Create params for certificate
const params = {
    identifiers: [{ type: "dns", value: options.domain }],
  };

# Set the validity period of the certificate if you need a period other than 1 year 
const date = new Date();
date.setFullYear(date.getFullYear() + options.yearsValid);
params.notAfter = date.toISOString();
params.notBefore = new Date().toISOString();

# Create order
const order = await client.newOrder(params);

# Get authorization
const authorization = await client.getAuthorization(order.result.authorizations[0]);

# Get Challange
const challange = authorization.result.challenges.filter((o) => o.type === "http-01")[0] as IHttpChallenge;

# Running a challenge on the server
await client.getChallenge(challange.url, "POST");

# Create CSR
const csr = await generateCSR(options.algorithm, options.domain);

# Complete a order
const finalize = await client.finalize(order.result.finalize, { csr: Convert.ToBase64Url(csr.csr) });

# Get certificate
const cert = await client.getCertificate(finalize.result.certificate);
console.log(res.result[0]);
```

# Testing ACME server

1. Clone the repo:
```sh
git clone https://github.com/microshine/acme-test.git
```

2. Dependency installation:
```sh
npm i
```

3. Fill in the data in .ENV file
URL_SERVER - controller address of the directory of the AKME server being tested
ALG_NAME - algorithm name (example RSASSA-PKCS1-v1_5)
ALG_HASH - algorithm hash (example SHA-256)
ALG_MODULUS_LENGTH - algorithm modulus length (example 2048)
IDENTIFIER_TYPE - identifier type
IDENTIFIER_VALUE - domain
CONTACT - (example mailto:example@gmail.com)
SERVER_TESTING - specify true to fully test the server at the specified address

4. Running tests
```sh
npm run test
```


