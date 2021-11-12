// Copyright 2020 Google LLC. SPDX-License-Identifier: Apache-2.0

import * as fs from "fs";
import * as crypto from "crypto";
import * as childProcess from "child_process";
import * as util from "util";
import * as sfv from "structured-field-values";
import cbor from "cbor";
import ed25519 from "noble-ed25519";
import express from "express";

const exec = util.promisify(childProcess.exec);

const { trust_token } = JSON.parse(fs.readFileSync("./package.json"));

const app = express();

app.use(express.static("."));

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/index.html");
});

app.get("/.well-known/trust-token/key-commitment", (req, res) => {
  console.log(req.path);
  const { ISSUER, protocol_version, batchsize, expiry, id } = trust_token;
  const Y = fs
    .readFileSync("./keys/pub_key.txt")
    .toString()
    .trim();

  const key_commitment = {}
  key_commitment[protocol_version] = {
    id,
    protocol_version,
    batchsize,
    keys: {
      "1": { Y, expiry }
    }
  };

  res.set({
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json; charset=utf-8"
  });

  res.send(JSON.stringify(key_commitment, "", " "));
});

app.post(`/.well-known/trust-token/issuance`, async (req, res) => {
  console.log(req.path);
  const sec_trust_token = req.headers["sec-trust-token"];
  console.log({ sec_trust_token });
  const result = await exec(`./bin/main --issue ${sec_trust_token}`);
  const token = result.stdout;
  console.log({ token })
  res.set({ "Access-Control-Allow-Origin": "*" });
  res.append("sec-trust-token", token);
  res.send();
});

app.post(`/.well-known/trust-token/redemption`, async (req, res) => {
  console.log(req.path);
  console.log(req.headers);
  const sec_trust_token_version = req.headers["sec-trust-token-version"];
  if (sec_trust_token_version !== "TrustTokenV3VOPRF") {
    return res.send(400);
  }
  const sec_trust_token = req.headers["sec-trust-token"];
  const result = await exec(`./bin/main --redeem ${sec_trust_token}`);
  const token = result.stdout;
  res.set({
    "Access-Control-Allow-Origin": "*"
  });
  res.append("sec-trust-token", token);
  res.send();
});

app.post(`/.well-known/trust-token/send-rr`, async (req, res) => {
  console.log(req.path);

  const headers = req.headers;
  console.log(headers);

  // sec-redemption-record
  // [(<issuer 1>, {"redemption-record": <SRR 1>}),
  //  (<issuer N>, {"redemption-record": <SRR N>})],
  const rr = sfv.decodeList(headers["sec-redemption-record"]);
  console.log(rr);
  const { value, params } = rr[0];
  const redemption_record = Buffer.from(params["redemption-record"]).toString();
  console.log({ redemption_record });

  // verify client_public_key
  const sec_signature = sfv.decodeDict(headers["sec-signature"]);
  console.log({ sec_signature });

  const signatures = sec_signature.signatures.value[0];
  const client_public_key = signatures.params["public-key"];
  console.log({ client_public_key });
  const sig = signatures.params["sig"];
  console.log({ sig });

  const destination = "trust-token-issuer-demo.glitch.me";

  // verify sec-signature
  const canonical_request_data = cbor.encode(
    new Map([
      ["sec-time", headers["sec-time"]],
      ["public-key", client_public_key],
      ["destination", destination],
      ["sec-redemption-record", headers["sec-redemption-record"]],
      [
        "sec-trust-tokens-additional-signing-data",
        headers["sec-trust-tokens-additional-signing-data"]
      ]
    ])
  );
  console.log(cbor.decode(canonical_request_data));

  const prefix = Buffer.from("TrustTokenV3");
  const signing_data = Buffer.concat([prefix, canonical_request_data]);
  const sig_verify = await ed25519.verify(sig, signing_data, client_public_key);

  console.log(sig_verify);

  res.set({
    "Access-Control-Allow-Origin": "*",
    "Feature-Policy": "trust-token-redemption *"
  });

  res.send({ sig_verify });
});

const listener = app.listen(process.env.PORT, () => {
  console.log(`listening on port ${listener.address().port}`);
});

process.on("unhandledRejection", err => {
  console.error(err);
});
