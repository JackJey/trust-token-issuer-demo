"use strict";
const $ = document.querySelector.bind(document);
const $$ = document.querySelectorAll.bind(document);
EventTarget.prototype.on = EventTarget.prototype.addEventListener;

function base64decode(str) {
  return new Uint8Array([...atob(str)].map(a => a.charCodeAt(0)));
}

document.on("DOMContentLoaded", async e => {
  console.log(e);

  const ISSUER = location.origin;
  
  $("#yes").on("click", async () => {
    // issuer request
    await fetch(`/.well-known/trust-token/issuance`, {
      method: "POST",
      trustToken: {
        type: "token-request",
        issuer: ISSUER
      }
    });

    // check token exists
    const token = await document.hasTrustToken(ISSUER);
    console.log(token);
  });
});
