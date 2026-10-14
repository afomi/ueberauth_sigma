defmodule Ueberauth.Strategy.Sigma.OAuth do
  @moduledoc """
  Calls to the Sigma issuer: the authorize URL, the signed code exchange,
  ID-token verification and userinfo.

      config :ueberauth, Ueberauth.Strategy.Sigma.OAuth,
        client_id: System.fetch_env!("SIGMA_CLIENT_ID"),
        member_wif: System.fetch_env!("SIGMA_MEMBER_WIF")

  Optional keys:

    * `:issuer` - defaults to `"https://auth.sigmaidentity.com"`.
    * `:redirect_uri` - the registered callback. Defaults to the callback URL
      Ueberauth builds from the request, which is wrong behind a proxy that
      terminates TLS; set it there.
    * `:req_options` - merged into every `Req` call (tests pass `plug:`).

  The member WIF signs each token request (`Sigma.BitcoinAuth`); its public
  key is the `accountPubkey` registered with the client. Sigma takes no client
  secret.
  """

  alias Sigma.BitcoinAuth

  @issuer "https://auth.sigmaidentity.com"
  @token_path "/api/auth/oauth2/token"

  def config do
    Application.fetch_env!(:ueberauth, __MODULE__)
    |> Keyword.put_new(:issuer, @issuer)
  end

  def authorize_url(params) do
    config()[:issuer] <> "/api/auth/oauth2/authorize?" <> URI.encode_query(params)
  end

  @doc """
  Exchanges an authorization code. Returns the token response, the verified
  ID-token claims and userinfo.
  """
  def exchange(code, verifier, redirect_uri, nonce) do
    config = config()

    with {:ok, tokens} <- token_request(config, code, verifier, redirect_uri),
         {:ok, claims} <- verify_id_token(config, tokens["id_token"], nonce),
         {:ok, user} <- userinfo(config, tokens["access_token"]),
         true <- user["sub"] == claims["sub"] || {:error, "userinfo", "subject mismatch"} do
      {:ok, %{tokens: tokens, claims: claims, user: user}}
    end
  end

  defp token_request(config, code, verifier, redirect_uri) do
    body =
      BitcoinAuth.form_encode([
        {"grant_type", "authorization_code"},
        {"code", code},
        {"redirect_uri", redirect_uri},
        {"client_id", config[:client_id]},
        {"code_verifier", verifier}
      ])

    req(config,
      method: :post,
      url: config[:issuer] <> @token_path,
      body: body,
      headers: [
        {"content-type", "application/x-www-form-urlencoded"},
        {"x-auth-token", BitcoinAuth.token(config[:member_wif], @token_path, body)}
      ]
    )
    |> case do
      {:ok, %{status: 200, body: %{"id_token" => _} = tokens}} ->
        {:ok, tokens}

      {:ok, %{status: 200}} ->
        {:error, "token", "no id_token; is the openid scope requested?"}

      {:ok, %{body: %{"error" => error} = body}} ->
        {:error, error, body["error_description"] || error}

      {:ok, %{status: status}} ->
        {:error, "token", "token endpoint answered #{status}"}

      {:error, exception} ->
        {:error, "token", Exception.message(exception)}
    end
  end

  defp verify_id_token(config, id_token, nonce) do
    with {:ok, %{status: 200, body: %{"keys" => keys}}} <-
           req(config, url: config[:issuer] <> "/api/auth/jwks"),
         %{"kid" => kid} <- JOSE.JWT.peek_protected(id_token).fields,
         %{} = key <- Enum.find(keys, &(&1["kid"] == kid)) || {:error, "id_token", "unknown key"},
         {true, %JOSE.JWT{fields: claims}, _} <-
           JOSE.JWT.verify_strict(JOSE.JWK.from_map(key), ["EdDSA"], id_token),
         :ok <- check_claims(claims, config, nonce) do
      {:ok, claims}
    else
      {:error, _, _} = error -> error
      {false, _, _} -> {:error, "id_token", "bad signature"}
      _ -> {:error, "id_token", "could not verify"}
    end
  end

  defp check_claims(claims, config, nonce) do
    cond do
      claims["iss"] != config[:issuer] -> {:error, "id_token", "wrong issuer"}
      config[:client_id] not in List.wrap(claims["aud"]) -> {:error, "id_token", "wrong audience"}
      claims["exp"] <= System.system_time(:second) -> {:error, "id_token", "expired"}
      claims["nonce"] != nonce -> {:error, "id_token", "wrong nonce"}
      true -> :ok
    end
  end

  defp userinfo(config, access_token) do
    case req(config,
           url: config[:issuer] <> "/api/auth/oauth2/userinfo",
           auth: {:bearer, access_token}
         ) do
      {:ok, %{status: 200, body: %{"sub" => _} = user}} -> {:ok, user}
      {:ok, %{status: status}} -> {:error, "userinfo", "userinfo answered #{status}"}
      {:error, exception} -> {:error, "userinfo", Exception.message(exception)}
    end
  end

  defp req(config, options) do
    options
    |> Keyword.merge(retry: false)
    |> Keyword.merge(Keyword.get(config, :req_options, []))
    |> Req.request()
  end
end
