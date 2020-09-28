const fs = require("fs");
const childProcess = require("child_process");
const util = require("util");
const exec = util.promisify(childProcess.exec);
const express = require("express");
const cbor = require("cbor");
const sh = require("structured-headers");
const ed25519 = require("ed25519");

const { trust_token } = require("./package.json");

const header = {
//  "sec-signature": `signatures=("https://trust-token-issuer.glitch.me";public-key=:YM9SYvtfcjBbqGhlSXHeR8ykMlaHo9iLyQIzRLefgNs=:;sig=:bI1qHHoDuwC6B5Loy16xBDuV3LZ+E3wxPGGqAxCCga86yFdljIc5mokDreBWD1KaLEV8XqqVt0GvGeWXuTENBg==:), sign-request-data=include`,
    "sec-signature": `s=("h";pub=abc;sig=def), srdata=include`,
  "sec-signed-redemption-record": `"https://trust-token-issuer.glitch.me";redemption-record=:Ym9keT06cEdodFpYUmhaR0YwWWFKbWNIVmliR2xqQVdkd2NtbDJZWFJsQUdwMGIydGxiaTFvWVhOb1dDRE5lU1htN2cxRTZWNXZHNFhLOWp0WWl5SlNEVmlubTNOeTRFQVRUdmRUZjJ0amJHbGxiblF0WkdGMFlhTm9hMlY1TFdoaGMyaFlJRC9VN01KRWJ6WVUrSU1CMXZZWjJQTkhkeWpsRzBKUUhsbUkwdmI4K1BPV2NISmxaR1ZsYldsdVp5MXZjbWxuYVc1NEpHaDBkSEJ6T2k4dmRISjFjM1F0ZEc5clpXNHRhWE56ZFdWeUxtZHNhWFJqYUM1dFpYUnlaV1JsYlhCMGFXOXVMWFJwYldWemRHRnRjQnBmYmdzMmNHVjRjR2x5ZVMxMGFXMWxjM1JoYlhBYVgyNEw2Zz09Oiwgc2lnbmF0dXJlPTorQzMvVmVWVUkxblRvaktndkpTWFRFNG5ualgxSjZmL0F5eXRVS1pQUGhHQlBFeVk3QjlONmtIYVMxenBFY1JZYml6TmR6bTNVUVdhVzFaNC9pV1VCQT09Og==:`,
  "sec-time": "2020-09-25T15:22:30.657Z",
  "sec-trust-tokens-additional-signing-data": "additional_signing_data",
  "signed-headers":
    "sec-signed-redemption-record,sec-time,sec-trust-tokens-additional-signing-data"
};

console.log(sh.parseDictionary(header['sec-signature']));
//console.log(sh.parseItem(header['sec-signature']));
console.log(sh.parseList(header['sec-signed-redemption-record']));
