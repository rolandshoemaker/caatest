# `caatest`

`caatest` is a simple CLI tool for checking for the presence of CAA records and their validity based on a specific issuer name based on the [RFC 6844 Section 4](https://tools.ietf.org/html/rfc6844#section-4) algorithm as amended by errata 5065.

## Usage

```
Usage of caatest:
	caatest [flags] domain-name
Flags:
  -issuer string
    	Name of issuer to test against (if empty exit code will always be 0 and full chain will be displayed)
  -resolver string
    	DNS server and port to send questions to (defaults to resolvers in /etc/resolv.conf if empty)
  -verbose
    	Print extra information about the CAA sets that are returned
```
