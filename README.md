# Ueberauth Sigma

An [Ueberauth](https://github.com/ueberauth/ueberauth) strategy for [Sigma Identity](https://sigmaidentity.com): OAuth 2.1 / OIDC sign-in where people hold Bitcoin keys and choose a BAP identity at consent.

Shared by Qart and VoteSmash.
Design notes: `qart/docs/SIGMA_AUTH.md`.

## What is different from other OAuth providers

Sigma takes no client secret.
Each client registers a secp256k1 member public key (`accountPubkey`) and the app signs every token request with the matching WIF, in an `X-Auth-Token` header (`Sigma.BitcoinAuth`).
The strategy also uses S256 PKCE and an OIDC nonce, and verifies the EdDSA ID token against Sigma's JWKS before reading userinfo.

## Install

```elixir
{:ueberauth_sigma, git: "https://github.com/afomi/ueberauth_sigma.git", branch: "main"}
```

## Register a client

1. `mix sigma.gen.member_key` prints a public key and a WIF. Make one per client.
2. At https://auth.sigmaidentity.com, under **OAuth Clients**, register the exact callback URL and the public key.
3. Put the client id and WIF in that deploy's secrets.

## Configure

```elixir
config :ueberauth, Ueberauth,
  providers: [sigma: {Ueberauth.Strategy.Sigma, []}]

config :ueberauth, Ueberauth.Strategy.Sigma.OAuth,
  client_id: System.fetch_env!("SIGMA_CLIENT_ID"),
  member_wif: System.fetch_env!("SIGMA_MEMBER_WIF"),
  # Behind a TLS-terminating proxy, give the registered callback explicitly.
  redirect_uri: "https://example.com/auth/sigma/callback"
```

The routes go through the session-fetching `:browser` pipeline; the PKCE verifier and nonce are kept in the session between the two phases.

## What a callback gives you

- `auth.uid`: the OIDC `sub`, the Sigma account. Key your identity rows on this.
- `auth.extra.raw_info.bap_id`: the BAP identity chosen at consent. One account can hold several.
- `auth.extra.raw_info.bap`: `id`, `rootAddress`, `currentAddress`, `identity`, when Sigma sends them.
- `auth.info.email`: only when Sigma marks it verified.

## Tests

`mix test`.
`test/fixtures/bitcoin_auth_vectors.json` was made with the npm packages `bitcoin-auth@0.0.8` and `@bsv/sdk@2.8.11`; tokens made here must match those byte for byte.

## Not implemented

The `brc77` signing scheme (Sigma accepts `bsm`), refresh, revocation and end-session.
