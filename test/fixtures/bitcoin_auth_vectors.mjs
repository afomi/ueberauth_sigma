// Regenerates bitcoin_auth_vectors.json from the reference npm packages:
//   npm install bitcoin-auth@0.0.8 @bsv/sdk@2.8.11   (in an empty directory)
//   node test/fixtures/bitcoin_auth_vectors.mjs <that directory>/node_modules > test/fixtures/bitcoin_auth_vectors.json
import { createRequire } from "node:module";
const require = createRequire(process.argv[2] + "/");
const { getAuthToken, verifyAuthToken } = require("bitcoin-auth");
const { PrivateKey } = require("@bsv/sdk");

const wif = PrivateKey.fromString("1".repeat(64), "hex").toWif();
const pubkey = PrivateKey.fromWif(wif).toPublicKey().toString();
const timestamp = "2026-10-14T18:00:00.000Z";
const requestPath = "/api/auth/oauth2/token";
const fields = [
  ["grant_type", "authorization_code"],
  ["code", "abc DEF~*-._!'()"],
  ["redirect_uri", "http://localhost:4000/auth/sigma/callback?x=1&y=é"],
  ["client_id", "qart-dev"],
  ["code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"],
];
const body = new URLSearchParams(fields).toString();
const bsm = getAuthToken({ privateKeyWif: wif, requestPath, body, scheme: "bsm", timestamp });
const bsmNoBody = getAuthToken({ privateKeyWif: wif, requestPath, scheme: "bsm", timestamp });
const brc77 = getAuthToken({ privateKeyWif: wif, requestPath, body, timestamp });
const check = (t, b) => verifyAuthToken(t, { requestPath, timestamp, body: b }, 5);
console.log(JSON.stringify({
  wif, pubkey, timestamp, request_path: requestPath, fields, body,
  bsm_token: bsm, bsm_token_no_body: bsmNoBody, brc77_token: brc77,
  self_check: [check(bsm, body), check(bsmNoBody, undefined), check(brc77, body)],
}, null, 2));
