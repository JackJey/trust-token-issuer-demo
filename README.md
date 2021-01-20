# Trust Token issuer demo

Token issuance using the Trust Token API based on [BoringSSL](https://boringssl.googlesource.com/boringssl/).

---

**Please note:** this demo does not provide code suitable for production use. The Trust Tokens 
API is still experimental, and is undergoing an [origin trial](https://web.dev/origin-trials) 
in Chrome. The Trust Tokens API and this demo may change without notice at any time.

---

## How to use

See [trust-token-demo.glitch.me](https://trust-token-demo.glitch.me).


## How to build

### BoringSSL

This demo requires BoringSSL. Run `./install-boringssl.sh` for download/build.

```sh
$ ./install-boringssl.sh
```

### Build c command

Build [c](./c) command with BoringSSL:

```sh
$ make
```

### Run HTTP server

Run the HTTP demo with express:

```sh
$ npm install
$ npm start
```

Note: you need a [Trust Tokens Origin Trial token](https://developers.chrome.com/origintrials/#/view_trial/2479231594867458049).


## API

### Key commitment

```
GET /.well-known/trust-token/key-commitment
```

`key-commitments` in JSON format for the browser.

### Issue request

```
POST /.well-known/trust-token/request
```

Trust Token issue request endpoint.

### Redemption

```
POST /.well-known/trust-token/redemption
```

SRR Token Redemption request endpoint.

### Send SRR

```
POST /.well-known/trust-token/send-srr
```

Send SRR endpoint, which echos back a `Sec-Signed-Redemtption-Record` 
header which the client sends as a response.


## Command

[bin/main](./bin/main) is build result of [c/main.c](c/main.c).

This command has flag for trust token operation.

```sh
$ main --issue $REQUEST
$ main --redeem $REQUEST
$ main --key-generate
```

### --issue

Take an issuance request (`Sec-Trust-Token HTTP Header`) and return an 
issuance response.

### --redeem

Take a redemption request (`Sec-Trust-Token HTTP Header`) and return 
a redemption response.

### --key-generate

Generate private/public keys for trust-token and ED25519 keypair.
Save them into files in the [./keys](./keys) directory.

===

Please note: this is not a Google product.