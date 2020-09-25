const fs = require("fs");
const childProcess = require("child_process");
const util = require("util");
const exec = util.promisify(childProcess.exec);
const express = require("express");
const cbor = require("cbor");
const sh = require('structured-headers');


const app = express();

app.use(express.static("."));

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/index.html");
});

app.get("/.well-known/trust-token/key-commitment", (req, res) => {
  console.log(req.path);
  const { trust_token } = require("./package.json");
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
    'Access-Control-Allow-Origin': '*',
  })

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
    'Access-Control-Allow-Origin': '*',
  })
  res.append("sec-trust-token", token);
  res.send();
});

app.post(`/.well-known/trust-token/redemption`, async (req, res) => {
  console.log(req.path);
  const sec_trust_token = req.headers["sec-trust-token"];
  const result = await exec(`./bin/main --redeem ${sec_trust_token}`);
  const token = result.stdout;
  res.set({
    'Access-Control-Allow-Origin': '*',
  })
  res.append("sec-trust-token", token);
  res.send();
});

function parseSRR(str) {
  return sh.parseList(str).map((srr) => {
    const issuer = srr.value
    const redemption_record = sh.parseDictionary(srr['parameters']['redemption-record'].toString())

    const result = {
      issuer: srr.value,
      record: {
        body: cbor.decodeAllSync(redemption_record.body.value).pop(),
        signature: redemption_record.signature.value
      }
    }

    console.log(result)
    return result
  })
}


app.post(`/.well-known/trust-token/send-srr`, async (req, res) => {
  console.log(req.path);
  const sec_signed_redemption_record =
    req.headers["sec-signed-redemption-record"];
  res.set({
    'Access-Control-Allow-Origin': '*',
  })

  const srr = parseSRR(sec_signed_redemption_record)
  
  console.log(srr)
  res.send(srr)
});

const listener = app.listen(process.env.PORT, () => {
  console.log(`listening on port ${listener.address().port}`);
});
