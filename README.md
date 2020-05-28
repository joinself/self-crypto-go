# self-crypto-go

[![GoDoc](https://godoc.org/github.com/selfid-net/self-crypto-go?status.svg)](https://godoc.org/github.com/selfid-net/self-crypto-go) [![Go Report Card](https://goreportcard.com/badge/github.com/selfid-net/self-crypto-go)](https://goreportcard.com/report/github.com/selfid-net/self-crypto-go) [![Build Status](https://travis-ci.com/selfid-net/self-crypto-go?branch=master)](https://travis-ci.com/selfid-net/self-crypto-go)

A end to end encryption library for self, built ontop of self's fork of [olm](https://gitlab.matrix.org/matrix-org/olm).

Group messaging is implemented with self's omemo implementation.

This library was originally based on [libolm-go](https://github.com/NotAFile/libolm-go).

## Requirements

This library requires the self fork of olm available on your system, in addition to self-omemo.


- [libself-olm](http://download.selfid.net/olm/libself-olm_0.1.14_amd64.deb)
- [libself-omemo](http://download.selfid.net/omemo/libself-omemo_0.1.0_amd64.deb)

## Installing

```
go get github.com/selfid-net/self-crypto-go
```

## Testing
```
go test -v
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/selfid-net/self-crypto-go.


## License

The repo is available as open source under the terms of the [Apache 2 License](LICENSE).
