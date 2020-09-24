"use strict";
const $ = document.querySelector.bind(document);
const $$ = document.querySelectorAll.bind(document);
EventTarget.prototype.on = EventTarget.prototype.addEventListener;

function base64decode(str) {
  return new Uint8Array([...atob(str)].map(a => a.charCodeAt(0)));
}

document.on("DOMContentLoaded", async e => {
  const ISSUER = location.origin;

  $("#yes").on("click", async () => {
    $("#issuing").style.visibility = "visible";

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

    if (token) {
      $("#issued").style.visibility = "visible";
    } else {
      // TODO: failure case
    }

    $("#back").style.visibility = "visible";

    setTimeout(() => {
      const query = new URLSearchParams(location.search);
      const back_url = query.get("back");
      location.href = back_url; // open redirecter !!?
    }, 1000);
  });

  $("#refresh").on("click", async() => {
    // redemption request
    await fetch(`/.well-known/trust-token/redemption`, {
      method: "POST",
      trustToken: {
        type: "srr-token-redemption",
        issuer: ISSUER,
        refreshPolicy: "refresh"
      }
    });   
  })
});
