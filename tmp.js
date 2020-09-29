'use strict';

const cbor = require("cbor");
const sfv = require("structured-field-values");
const ed25519 = require("noble-ed25519");
const fs = require("fs");
const crypto = require('crypto');

async function main() {

  const headers = {
    "sec-signature":                            `signatures=("https://trust-token-issuer.glitch.me";public-key=:ToV8pRJJlDkgQhWhDHl4+1zge/Ri4k3VArX1fevI/hE=:;sig=:spI+/Fy+/iSpozJE2au8MphZqKHgP3ruuF6v2YTdZklOyv+LgTbV4ZtmCRjsJMqJAthC8WVlVCXOwP49wEXPAQ==:), sign-request-data=include`,
    "sec-signed-redemption-record":             `"https://trust-token-issuer.glitch.me";redemption-record=:Ym9keT06cEdodFpYUmhaR0YwWWFKbWNIVmliR2xqQVdkd2NtbDJZWFJsQVdwMGIydGxiaTFvWVhOb1dDQ1hFQXlYem9rVzBXKzgxVDNLRWFyYlpPeElwOFVNUnNmTit1L09nUE1VSEd0amJHbGxiblF0WkdGMFlhTm9hMlY1TFdoaGMyaFlJSlBpS2x6SEwrc3BGTVhnakxJRlUwejV2bjMvTGFOWFduYnRYNExOS3F2SmNISmxaR1ZsYldsdVp5MXZjbWxuYVc1NEpHaDBkSEJ6T2k4dmRISjFjM1F0ZEc5clpXNHRhWE56ZFdWeUxtZHNhWFJqYUM1dFpYUnlaV1JsYlhCMGFXOXVMWFJwYldWemRHRnRjQnBmY3dQNWNHVjRjR2x5ZVMxMGFXMWxjM1JoYlhBYVgzTUVyUT09Oiwgc2lnbmF0dXJlPTpYcUdDYmZpWE1sSjVxTDJmc3RsNXg1ckJueDJOSU1ZZTFPdVJRbWVLNDM0WjBiTXdFODYweGtBbTJIM2lDY0VWRFhZRXI3L283T1ZZYTlPSkozc0dDUT09Og==:`,
    "sec-time":                                 `2020-09-29T09:52:57.682Z`,
    "sec-trust-tokens-additional-signing-data": `additional_signing_data`,
    "signed-headers":                           `sec-signed-redemption-record,sec-time,sec-trust-tokens-additional-signing-data`,
  }

  // sec-signed-redemption-record
  // [(<issuer 1>, {"redemption-record": <SRR 1>}),
  //  (<issuer N>, {"redemption-record": <SRR N>})],
  const srr = sfv.parseList(headers["sec-signed-redemption-record"]);
  const redemption_record   = sfv.parseDict(Buffer.from(srr[0]["params"]["redemption-record"]).toString())

  const { body, signature } = redemption_record

  // verify signature
  const srr_public_key = Buffer.from(fs.readFileSync("./keys/srr_pub_key.txt").toString(), "base64")
  const signed         = await ed25519.verify(signature.value, body.value, srr_public_key)
  console.log({signed})

  // {
  //   // The values in "client-data" are all provided alongside the signed token in the client's redemption request.
  //   'client-data': {
  //     // CBOR type "unsigned integer. <Redemption timestamp, seconds past the Unix epoch>"
  //     'redemption-timestamp': 1601356252
  //
  //     // CBOR type "text string."  <Top-level origin at the time of redemption>,
  //     'redeeming-origin': 'https://trust-token-issuer.glitch.me',
  //
  //     // CBOR type "byte string SHA256(client public key)
  //     'key-hash': <Buffer 98 23 8f eb 15 9a 08 24 08 02 85 a3 65 46 7e be 52 5d 1d 42 6d b0 fd a2 aa cd ad b3 92 fa bb d2>,
  //   },
  //
  //   // CBOR type "byte string".  SHA256(redeemed token),
  //   'token-hash': <Buffer fa a0 2e 84 b0 7d a9 9c 7a 3a 57 81 b9 13 74 35 1a c8 8f 92 0e 5f 1f a7 59 94 35 3e c1 80 6c 66>,
  //   'metadata': {
  //     // For v0, this is an integer (of CBOR type "unsigned integer") with value in the representable range of uint32_t. <Key label (from its key commitment) used for the redeemed token>,
  //     'public': 1,
  //     // For v0, this is an integer (of CBOR type "unsigned integer") with value in the representable range of uint8_t storing the encrypted value of 0 or 1. <An encoded check bit>
  //     'private': 0
  //   },
  //   // CBOR type "unsigned integer"
  //   // Eventually, we may require the expiry agree with a fixed SRR lifetime
  //   // duration declared in the issuer's key commitment log. For v0, this might not
  //   // be enforced.
  //   // <optional expiry timestamp, seconds past the Unix epoch>
  //   'expiry_timestamp': 1601356432
  // }
  const srr_body = cbor.decodeAllSync(Buffer.from(body.value))[0]
  const metadata         = srr_body['metadata']
  const token_hash       = srr_body['token-hash']
  const client_data      = srr_body['client-data']
  const    key_hash            = client_data['key-hash']
  const    redeeming_origin    = client_data['redeeming_origin']
  const    redeeming_timestamp = client_data['redeeming_timestamp']
  const expiry_timestamp = srr_body['expiry-timestamp']


  // sec-signature
  // {
  //   'signatures': {
  //     value: [
  //       {
  //         value: 'https://trust-token-issuer.glitch.me',
  //         params: {
  //           'public-key': <Buffer 4d 2d 4b df 1e b3 d7 7a c8 64 67 3f 6f a0 9e e9 d3 7d 50 d5 f8 68 03 3d 2e 05 a5 a8 e4 20 a3 4f>
  //           'sig': <Buffer 9e 1b ef b3 e1 4c 7b fe 1f 59 b8 49 a1 36 db 28 9f 31 c8 17 37 34 df d9 3d 34 b2 97 4a 98 a1 2a d5 d4 4a 90 3b 74 c8 79 21 c2 e7 26 c2 d4 fe ff 84 2d ... 14 more bytes>
  //         }
  //       }
  //     ],
  //     params: {}
  //   },
  //   'sign-request-data': {
  //     value: 'include',
  //     params: {}
  //   }
  // }
  const sec_signature     = sfv.parseDict(headers["sec-signature"])
  const client_public_key = sec_signature.signatures.value[0].params['public-key']
  const sig               = sec_signature.signatures.value[0].params['sig']


  const client_public_key_hash = crypto.createHash('sha256').update(client_public_key).digest();

  console.log({client_public_key: client_public_key_hash.toString() === key_hash.toString()})

  // const canonical_request_data = cbor.encode({
  //   "destination":                              "trust-token-issuer.glitch.me",
  //   "sec-signed-redemption-record":             headers["sec-signed-redemption-record"],
  //   "sec-time":                                 headers["sec-time"],
  //   "sec-trust-tokens-additional-signing-data": headers["sec-trust-tokens-additional-signing-data"],
  //   "pk":                                       client_public_key,
  // })

  const canonical_request_data = cbor.encode(new Map([
     ["destination",                              "trust-token-issuer.glitch.me",                     ],
     ["sec-signed-redemption-record",             headers["sec-signed-redemption-record"],            ],
     ["sec-time",                                 headers["sec-time"],                                ],
     ["sec-trust-tokens-additional-signing-data", headers["sec-trust-tokens-additional-signing-data"],],
     ["pk",                                       client_public_key,                                  ],
  ]))

  const prefix       = Buffer.from("Trust Token v0")
  const signing_data = Buffer.concat([prefix, canonical_request_data])

  console.log(await ed25519.verify(sig, signing_data, client_public_key))
}

main()
