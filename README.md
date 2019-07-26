# The Peculiar Authentication and User Management API

## Overview

AKME-client is a module that is designed to test AKME servers.

## Getting Started

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

4. Running tests
```sh
npm run test
```


