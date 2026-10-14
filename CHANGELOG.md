# Changelog

## 0.1.0 (unreleased)

- `Ueberauth.Strategy.Sigma`: authorization-code sign-in with S256 PKCE, an OIDC nonce, an `iss` check, EdDSA ID-token verification against the issuer's JWKS, and userinfo.
- `Sigma.BitcoinAuth`: `X-Auth-Token` signing and verification in the `bitcoin-auth` format, `bsm` scheme only; form encoding identical to `URLSearchParams`.
- `mix sigma.gen.member_key`: prints a new client member key.
