const fs = require("fs");
const childProcess = require("child_process");
const util = require("util");
const exec = util.promisify(childProcess.exec);
const express = require("express");
const cbor = require("cbor");
const sfv = require("structured-field-values");
const ed25519 = require("noble-ed25519");

const { trust_token } = require("./package.json");

const app = express();

app.use(express.static("."));

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/index.html");
});

app.get("/.well-known/trust-token/key-commitment", (req, res) => {
  console.log(req.path);
  const { ISSUER, protocol_version, batchsize, expiry } = trust_token;
  const srrkey = fs
    .readFileSync("./keys/srr_pub_key.txt")
    .toString()
    .trim();
  const Y = fs
    .readFileSync("./keys/pub_key.txt")
    .toString()
    .trim();

  const COMMITMENT = {};
  COMMITMENT[ISSUER] = {
    protocol_version,
    batchsize,
    srrkey,
    "1": { Y, expiry }
  };

  res.set({
    "Access-Control-Allow-Origin": "*"
  });

  res.json({
    ISSUER,
    COMMITMENT
  });
});

app.post(`/.well-known/trust-token/issuance`, async (req, res) => {
  console.log(req.path);
  const sec_trust_token = req.headers["sec-trust-token"];
  const result = await exec(`./bin/main --issue ${sec_trust_token}`);
  const token = result.stdout;
  res.set({
    "Access-Control-Allow-Origin": "*"
  });
  res.append("sec-trust-token", token);
  res.send();
});

app.post(`/.well-known/trust-token/redemption`, async (req, res) => {
  console.log(req.path);
  const sec_trust_token = req.headers["sec-trust-token"];
  const result = await exec(`./bin/main --redeem ${sec_trust_token}`);
  const token = result.stdout;
  res.set({
    "Access-Control-Allow-Origin": "*"
  });
  res.append("sec-trust-token", token);
  res.send();
});

app.post(`/.well-known/trust-token/send-srr`, async (req, res) => {
  console.log(req.path);
  const srr               = sfv.parseList(req.headers["sec-signed-redemption-record"]);
  const redemption_record = sfv.parseDict(Buffer.from(srr[0]['params']['redemption-record']).toString())
  const {body, signature} = redemption_record
  const public_key        = Buffer.from(fs.readFileSync("./keys/srr_pub_key.txt").toString(), 'base64')
  const signed = await ed25519.verify(signature.value, body.value, public_key);

  console.log(signed)

  res.set({
    "Access-Control-Allow-Origin": "*"
  });
   
  res.send({signed});
});

const listener = app.listen(process.env.PORT, () => {
  console.log(`listening on port ${listener.address().port}`);
});
