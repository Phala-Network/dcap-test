DCAP Test
====

A simple tool to test DCAP quote generation and fetch quote collateral.

## Requirements

- Hardware with DCAP support
- Gramine
- SGX AESM with QE and QPL

## Build

Require HW SGX

```
cd gramine-build
SGX_SIGNER_KEY=private.dev.pem make dist PREFIX=../bin
```

## Run

```
cd bin
./gramine-sgx dcap-test
```

## References

- https://download.01.org/intel-sgx/sgx-dcap/1.19/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf

## License

MIT. Third-party vendors (/vendors) released under their own licenses.
