This package implements TLS protocol (SSL 3.0 and TLS 1.0, 1.1 and 1.2).

	**Currently early WIP**

# Goals

* highly modular to enable use of different cryptographic modules, certificate stores, session caches, etc
* well factored and documented for clarity and suitability for future development (new protocol versions, extensions, experiments, etc.)
* scalable (buffer management, minimize garbage, minimize number of external calls, etc)

# Features

## Record Layer

* [x] Reader and Writer interface
* [x] HMAC & SSL 3.0 MAC (MD5, SHA, SHA256)
* [x] StreamCipher (NULL, RC4_128)
* [x] BlockCipher, implicit & explicit IV (3DES_EDE_CBC, AES_128_CBC, AES_256_CBC)
* [ ] AEADCipher

## Handshake

* [ ] RSA Key Exchange
* [ ] DHE Key Exchange
* [ ] ECDHE Key Exchange
* [ ] Certificate Store
* [ ] Session Cache
* [ ] Session Resumption
* [ ] Renegotiation

## Handshake Extensions

* [ ] Signature Algorithms, TLS 1.2
* [ ] Server Name, RFC#6066
* [ ] Renegotiation Info, RFC#5746
* [ ] Session Tickets, RFC#5077

# Status

Currently it is possible to exercise the records package (tests or benchmarks) with either the native Go crypto library or with OpenSSL's libcrypto. Which one is used is controlled via imports (okapi/gocrypto or okapi/libcrypto). The tests are set up to use libcrypto by default, but can be easily switched to gocrypto with GOCRYPTO build tag.

```
$ go test -bench=RW
PASS
BenchmarkRW_NULL_NULL_TLS10	  500000	      5750 ns/op
BenchmarkRW_NULL_MD5_SSL30	   10000	    105334 ns/op
BenchmarkRW_NULL_SHA_TLS11	  200000	     14569 ns/op
BenchmarkRW_RC4_128_MD5_SSL30	   10000	    210437 ns/op
BenchmarkRW_RC4_128_SHA_TSL12	   10000	    117597 ns/op
BenchmarkRW_3DES_EDE_CBC_SHA_SSL30	    2000	   1417936 ns/op
BenchmarkRW_AES_128_CBC_SHA_TLS10	   50000	     51434 ns/op
BenchmarkRW_AES_256_CBC_SHA256_TLS12	   20000	     87873 ns/op
ok  	_/Users/martin/go/tls/records	19.122s
```

```
$ go test -bench=RW -tags=GOCRYPTO
PASS
BenchmarkRW_NULL_NULL_TLS10	  500000	      5776 ns/op
BenchmarkRW_NULL_MD5_SSL30	   20000	     86158 ns/op
BenchmarkRW_NULL_SHA_TLS11	   10000	    112762 ns/op
BenchmarkRW_RC4_128_MD5_SSL30	   10000	    136175 ns/op
BenchmarkRW_RC4_128_SHA_TSL12	   10000	    162692 ns/op
BenchmarkRW_3DES_EDE_CBC_SHA_SSL30	     200	   7550312 ns/op
BenchmarkRW_AES_128_CBC_SHA_TLS10	    5000	    340585 ns/op
BenchmarkRW_AES_256_CBC_SHA256_TLS12	    5000	    699540 ns/op
ok  	_/Users/martin/go/tls/records	17.306s
```
