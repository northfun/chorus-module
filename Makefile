.PHONY: test

test:
	go test ./lib/go-crypto
	go test ./xlib
	go test ./xlib/crypto
	go test ./xlib/mlist
