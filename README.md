# ocsprf

[![Gem Version](https://badge.fury.io/rb/ocsprf.svg)](https://badge.fury.io/rb/ocsprf)
[![Actions Status](https://github.com/thekuwayama/ocsprf/workflows/CI/badge.svg)](https://github.com/thekuwayama/ocsprf/actions?workflow=CI)
[![Maintainability](https://api.codeclimate.com/v1/badges/4d5bb71e2dca46f5a239/maintainability)](https://codeclimate.com/github/thekuwayama/ocsprf/maintainability)

`ocsprf` is OCSP Response Fetch CLI.

- https://datatracker.ietf.org/doc/html/rfc6960


## Installation

The gem is available at [rubygems.org](https://rubygems.org/gems/ocsprf). You can install it the following.

```bash
$ gem install ocsprf
```


## Usage

```bash
$ ocsprf --help
Usage: ocsprf [options] PATH
    -i, --issuer PATH                issuer certificate path
    -o, --output PATH                output file path
    -s, --strict                     strict mode                   (default false)
    -v, --verbose                    verbose mode                  (default false)
```

You can run it the following and print the DER-encoded OCSP Response that fetched.

```bash
$ ocsprf /path/to/subject/certificate
$DER_BINARY
```

If you need to print OCSP Response text, you can run it the following.

```bash
$ ocsprf /path/to/subject/certificate --verbose > /dev/null
OCSP Response Data:
    OCSP Response Status: (0x0)
    Responses:
    Certificate ID:
      Hash Algorithm: sha1
      Issuer Name Hash: 0123456789ABCDEF0123456789ABCDEF01234567
      Issuer Key Hash: 0123456789ABCDEF0123456789ABCDEF01234567
      Serial Number: 0123456789ABCDEF0123456789ABCDEF01234567
    Cert Status: good
    This Update: 2020-01-01 12:00:00 UTC
    Next Update: 2020-01-08 12:00:00 UTC
```

If you have the issuer certificate corresponding to the subject certificate, you can pass it using `--issuer` option.
By default, `ocsprf` tries to get the issuer certificate using AIA extension.

```bash
$ ocsprf /path/to/subject/certificate --issuer /path/to/issuer/certificate --verbose > /dev/null
OCSP Response Data:
    OCSP Response Status: (0x0)
    Responses:
    Certificate ID:
      Hash Algorithm: sha1
      Issuer Name Hash: 0123456789ABCDEF0123456789ABCDEF01234567
      Issuer Key Hash: 0123456789ABCDEF0123456789ABCDEF01234567
      Serial Number: 0123456789ABCDEF0123456789ABCDEF01234567
    Cert Status: good
    This Update: 2020-01-01 12:00:00 UTC
    Next Update: 2020-01-08 12:00:00 UTC
```


## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
