defmodule Ueberauth.Strategy.SigmaTest do
  use ExUnit.Case, async: true

  import Plug.Test
  import Plug.Conn

  alias Sigma.BitcoinAuth

  @issuer "https://auth.sigmaidentity.com"
  @secret_key_base String.duplicate("k", 64)
  @provider {Ueberauth.Strategy.Sigma, []}
  @member_pubkey "test/fixtures/bitcoin_auth_vectors.json"
                 |> File.read!()
                 |> Jason.decode!()
                 |> Map.fetch!("pubkey")

  setup do
    jwk = JOSE.JWK.generate_key({:okp, :Ed25519})
    {:ok, jwk: jwk}
  end

  test "the request phase redirects to Sigma with PKCE, nonce and state" do
    conn = request()
    query = authorize_query(conn)

    assert query["client_id"] == "qart-test"
    assert query["response_type"] == "code"
    assert query["scope"] == "openid profile email"
    assert query["code_challenge_method"] == "S256"
    assert query["redirect_uri"] == "http://www.example.com/auth/sigma/callback"
    assert is_binary(query["state"])
    assert Map.has_key?(conn.resp_cookies, "ueberauth.state_param")

    %{"verifier" => verifier, "nonce" => nonce} = get_session(conn, "ueberauth_sigma")
    assert query["nonce"] == nonce

    assert query["code_challenge"] ==
             Base.url_encode64(:crypto.hash(:sha256, verifier), padding: false)
  end

  test "a callback signs the exchange and returns the account and its BAP identity", %{jwk: jwk} do
    conn = sign_in(jwk)

    assert %Ueberauth.Auth{} = auth = conn.assigns.ueberauth_auth
    assert auth.provider == :sigma
    assert auth.uid == "account-1"
    assert auth.info.name == "Ada"
    assert auth.info.email == "ada@example.com"
    assert auth.extra.raw_info.bap_id == "bap-1"
    assert auth.extra.raw_info.bap["rootAddress"] == "1Root"
    assert auth.credentials.token == "access-1"
    assert get_session(conn, "ueberauth_sigma") == nil
  end

  test "an unverified email is left out", %{jwk: jwk} do
    conn = sign_in(jwk, user: %{"email_verified" => false})
    assert conn.assigns.ueberauth_auth.info.email == nil
  end

  test "an ID token for another client is refused", %{jwk: jwk} do
    assert errors(sign_in(jwk, claims: %{"aud" => "someone-else"})) == [
             {"id_token", "wrong audience"}
           ]
  end

  test "an ID token with another nonce is refused", %{jwk: jwk} do
    assert errors(sign_in(jwk, claims: %{"nonce" => "replayed"})) == [{"id_token", "wrong nonce"}]
  end

  test "an ID token signed by another key is refused", %{jwk: jwk} do
    other = JOSE.JWK.generate_key({:okp, :Ed25519})
    assert errors(sign_in(jwk, signing_key: other)) == [{"id_token", "bad signature"}]
  end

  test "a callback from another issuer is refused before any exchange", %{jwk: jwk} do
    assert errors(sign_in(jwk, iss: "https://evil.example")) == [{"iss", "wrong issuer"}]
  end

  test "a token error from Sigma is passed on", %{jwk: jwk} do
    conn =
      sign_in(jwk,
        token_status: 401,
        token_body: %{"error" => "invalid_client", "error_description" => "no"}
      )

    assert errors(conn) == [{"invalid_client", "no"}]
  end

  test "a callback without a sign-in in progress is refused" do
    requested = request()
    state = authorize_query(requested)["state"]
    conn = callback(requested, %{"code" => "c", "state" => state}, %{})

    assert errors(conn) == [{"pkce", "No sign-in in progress"}]
  end

  test "access denied at Sigma is a failure, not a crash" do
    requested = request()
    state = authorize_query(requested)["state"]
    conn = callback(requested, %{"error" => "access_denied", "state" => state}, %{})

    assert errors(conn) == [{"access_denied", "access_denied"}]
  end

  defp request do
    conn(:get, "/auth/sigma")
    |> Map.put(:secret_key_base, @secret_key_base)
    |> init_test_session(%{})
    |> fetch_query_params()
    |> Ueberauth.run_request(:sigma, @provider)
  end

  defp callback(requested, params, session) do
    conn(:get, "/auth/sigma/callback?" <> URI.encode_query(params))
    |> recycle_cookies(requested)
    |> Map.put(:secret_key_base, @secret_key_base)
    |> init_test_session(session)
    |> fetch_query_params()
    |> Ueberauth.run_callback(:sigma, @provider)
  end

  defp authorize_query(conn) do
    [location] = get_resp_header(conn, "location")
    assert String.starts_with?(location, @issuer <> "/api/auth/oauth2/authorize?")
    location |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
  end

  defp sign_in(jwk, overrides \\ []) do
    requested = request()
    query = authorize_query(requested)
    %{"verifier" => verifier} = get_session(requested, "ueberauth_sigma")

    user =
      Map.merge(
        %{
          "sub" => "account-1",
          "name" => "Ada",
          "email" => "ada@example.com",
          "email_verified" => true,
          "bap_id" => "bap-1",
          "bap" => ~s({"id":"bap-1","rootAddress":"1Root"})
        },
        overrides[:user] || %{}
      )

    claims =
      Map.merge(
        %{
          "iss" => @issuer,
          "aud" => "qart-test",
          "sub" => "account-1",
          "exp" => System.system_time(:second) + 60,
          "nonce" => query["nonce"]
        },
        overrides[:claims] || %{}
      )

    id_token =
      (overrides[:signing_key] || jwk)
      |> JOSE.JWT.sign(%{"alg" => "EdDSA", "kid" => "k1"}, claims)
      |> JOSE.JWS.compact()
      |> elem(1)

    Req.Test.stub(Ueberauth.Strategy.Sigma, fn conn ->
      case conn.request_path do
        "/api/auth/oauth2/token" ->
          {:ok, body, conn} = read_body(conn)
          [token] = get_req_header(conn, "x-auth-token")
          form = URI.decode_query(body)

          # What Sigma checks: the registered key signed this exact body,
          # and the verifier matches the challenge.
          assert BitcoinAuth.verify(token, "/api/auth/oauth2/token", body) ==
                   {:ok, @member_pubkey}

          assert Base.url_encode64(:crypto.hash(:sha256, form["code_verifier"]), padding: false) ==
                   query["code_challenge"]

          assert form["code"] == "code-1"
          assert form["redirect_uri"] == query["redirect_uri"]

          conn
          |> put_status(overrides[:token_status] || 200)
          |> Req.Test.json(
            overrides[:token_body] ||
              %{
                "access_token" => "access-1",
                "token_type" => "Bearer",
                "expires_in" => 3600,
                "scope" => "openid profile email",
                "id_token" => id_token
              }
          )

        "/api/auth/jwks" ->
          {_, public} = JOSE.JWK.to_public_map(jwk)
          Req.Test.json(conn, %{"keys" => [Map.put(public, "kid", "k1")]})

        "/api/auth/oauth2/userinfo" ->
          assert get_req_header(conn, "authorization") == ["Bearer access-1"]
          Req.Test.json(conn, user)
      end
    end)

    callback(
      requested,
      %{"code" => "code-1", "state" => query["state"], "iss" => overrides[:iss] || @issuer},
      %{"ueberauth_sigma" => %{"verifier" => verifier, "nonce" => query["nonce"]}}
    )
  end

  defp errors(conn) do
    assert %Ueberauth.Failure{errors: errors} = conn.assigns.ueberauth_failure
    Enum.map(errors, &{&1.message_key, &1.message})
  end
end
