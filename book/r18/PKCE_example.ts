import * as CryptoJS from "crypto-js";
import * as CryptoRandomString from "crypto-random-string";

function base64URL(s: any) {
  return s
    .toString(CryptoJS.enc.Base64)
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

const codeVerifier = CryptoRandomString({ length: 128 }); // Zalecana długość to 43-128 znaków
const codeChallenge = base64URL(CryptoJS.SHA256(codeVerifier));

console.debug("Code Verifier:", codeVerifier);
console.debug("Code Challenge:", codeChallenge);
