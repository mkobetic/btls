This package implements TLS protocol (SSL 3.0 and TLS 1.0, 1.1 and 1.2).

	**Currently early WIP**

# Goals

* highly modular to enable use of different cryptographic modules, certificate stores, session caches, etc
* well factored and documented for clarity and extensibility
* suitable for future development (new protocol versions, extensions, experiments, etc.)
* scalable (buffer management, minimize garbage, minimize number of external calls, etc)

# Features

## Record Layer

[x] Reader and Writer interface
[x] HMAC & SSL 3.0 MAC (MD5, SHA, SHA256)
[x] StreamCipher (NULL, RC4_128)
[x] BlockCipher, implicit & explicit IV (3DES_EDE_CBC, AES_128_CBC, AES_256_CBC)
[ ] AEADCipher

## Handshake

[ ] Certificate Store
[ ] RSA Key Exchange
[ ] DHE Key Exchange
[ ] ECDHE Key Exchange
[ ] Session Cache
[ ] Session Resumption
[ ] Renegotiation

## Handshake Extensions

[ ] Signature Algorithms, TLS 1.2
[ ] Server Name, RFC#6066
[ ] Renegotiation Info, RFC#5746
[ ] Session Tickets, RFC#5077

## Other

## Command line tool

[ ] benchmarking
[ ] test server
[ ] test client
[ ] file transfer
