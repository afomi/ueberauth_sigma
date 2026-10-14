defmodule Ueberauth.Strategy.Sigma do
  @moduledoc """
  Sign in with Sigma Identity (https://sigmaidentity.com).

      config :ueberauth, Ueberauth,
        providers: [sigma: {Ueberauth.Strategy.Sigma, []}]

  and configure `Ueberauth.Strategy.Sigma.OAuth`.

  Ueberauth checks `state`. This strategy adds an S256 PKCE verifier and an
  OIDC nonce, kept in the Plug session between the two phases (so the session
  must be fetched), checks the `iss` callback parameter, exchanges the code
  with a signed `X-Auth-Token`, and verifies the ID token before reading
  userinfo.

  The result:

    * `uid` - the OIDC `sub`, the Sigma account.
    * `info` - `name`, `image`, and `email` only when Sigma says it is verified.
    * `extra.raw_info` - `bap_id`, the BAP identity chosen at consent (one
      account can hold several), `bap` decoded when it is JSON text, and the
      full `user` and `claims`.
  """

  use Ueberauth.Strategy,
    uid_field: "sub",
    default_scope: "openid profile email"

  alias Ueberauth.Auth.{Credentials, Extra, Info}
  alias Ueberauth.Strategy.Sigma.OAuth

  @session_key "ueberauth_sigma"

  def handle_request!(conn) do
    verifier = random()
    nonce = random()

    params =
      [
        client_id: OAuth.config()[:client_id],
        redirect_uri: redirect_uri(conn),
        response_type: "code",
        scope: conn.params["scope"] || option(conn, :default_scope),
        code_challenge: Base.url_encode64(:crypto.hash(:sha256, verifier), padding: false),
        code_challenge_method: "S256",
        nonce: nonce
      ]
      |> with_state_param(conn)

    conn
    |> put_session(@session_key, %{"verifier" => verifier, "nonce" => nonce})
    |> redirect!(OAuth.authorize_url(params))
  end

  def handle_callback!(%Plug.Conn{params: %{"code" => code} = params} = conn) do
    pkce = get_session(conn, @session_key)
    conn = delete_session(conn, @session_key)

    with %{"verifier" => verifier, "nonce" => nonce} <- pkce,
         true <-
           params["iss"] in [nil, OAuth.config()[:issuer]] || {:error, "iss", "wrong issuer"},
         {:ok, result} <- OAuth.exchange(code, verifier, redirect_uri(conn), nonce) do
      conn
      |> put_private(:sigma_user, result.user)
      |> put_private(:sigma_claims, result.claims)
      |> put_private(:sigma_tokens, result.tokens)
    else
      nil -> set_errors!(conn, [error("pkce", "No sign-in in progress")])
      {:error, key, message} -> set_errors!(conn, [error(key, message)])
    end
  end

  def handle_callback!(%Plug.Conn{params: %{"error" => error} = params} = conn) do
    set_errors!(conn, [error(error, params["error_description"] || error)])
  end

  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  def handle_cleanup!(conn) do
    conn
    |> put_private(:sigma_user, nil)
    |> put_private(:sigma_claims, nil)
    |> put_private(:sigma_tokens, nil)
  end

  def uid(conn), do: conn.private.sigma_user[option(conn, :uid_field)]

  def info(conn) do
    user = conn.private.sigma_user

    %Info{
      name: user["name"],
      first_name: user["given_name"],
      last_name: user["family_name"],
      email: if(user["email_verified"] == true, do: user["email"]),
      image: user["picture"]
    }
  end

  def credentials(conn) do
    tokens = conn.private.sigma_tokens
    expires_at = tokens["expires_in"] && System.system_time(:second) + tokens["expires_in"]

    %Credentials{
      token: tokens["access_token"],
      refresh_token: tokens["refresh_token"],
      token_type: tokens["token_type"],
      expires: expires_at != nil,
      expires_at: expires_at,
      scopes: String.split(tokens["scope"] || "", " ", trim: true)
    }
  end

  def extra(conn) do
    user = conn.private.sigma_user

    %Extra{
      raw_info: %{
        bap_id: user["bap_id"],
        bap: decode_bap(user["bap"]),
        user: user,
        claims: conn.private.sigma_claims
      }
    }
  end

  defp decode_bap(bap) when is_binary(bap) do
    case Jason.decode(bap) do
      {:ok, %{} = decoded} -> decoded
      _ -> nil
    end
  end

  defp decode_bap(bap) when is_map(bap), do: bap
  defp decode_bap(_), do: nil

  defp redirect_uri(conn), do: OAuth.config()[:redirect_uri] || callback_url(conn)

  defp option(conn, key), do: Keyword.get(options(conn), key, Keyword.get(default_options(), key))

  defp random, do: Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)
end
