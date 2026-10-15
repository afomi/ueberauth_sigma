defmodule Sigma.BitcoinAuth do
  @moduledoc """
  Signed request tokens in the format of the `bitcoin-auth` npm package,
  as sent in Sigma's `X-Auth-Token` header.

      pubkey|scheme|timestamp|requestPath|signature

  The signed message is `"requestPath|timestamp|sha256_hex(body)"` (an empty
  hash part when there is no body). Only the `bsm` scheme (Bitcoin Signed
  Message) is implemented; Sigma's verifier accepts `bsm` and `brc77`.

  Signatures are deterministic (RFC 6979), so a token made here for a given
  key, path, body and timestamp is byte-identical to the npm package's.
  """

  alias BSV.{Message, PrivKey, PubKey}

  # WIF version bytes: mainnet, testnet.
  @wif_versions [<<0x80>>, <<0xEF>>]

  @doc """
  Makes a token for `request_path` and `body` with a WIF private key.
  """
  @spec token(String.t(), String.t(), String.t() | nil, String.t()) :: String.t()
  def token(wif, request_path, body \\ nil, timestamp \\ now()) do
    privkey = privkey_from_wif!(wif)
    signature = Message.sign(message(request_path, timestamp, body), privkey)

    Enum.join([pubkey_hex(privkey), "bsm", timestamp, request_path, signature], "|")
  end

  @doc """
  Verifies a `bsm` token against the request it should cover.

  The token's path must equal `request_path`, its timestamp must be no more
  than `max_skew` seconds from now in either direction, and its signature must
  cover `body`. Returns `{:ok, pubkey_hex}` so the caller can check the key is
  one it authorizes; a valid signature alone authorizes nothing.
  """
  @spec verify(String.t(), String.t(), String.t() | nil, keyword()) ::
          {:ok, String.t()} | {:error, atom()}
  def verify(token, request_path, body \\ nil, opts \\ []) do
    max_skew = Keyword.get(opts, :max_skew, 300)
    now = Keyword.get(opts, :now, DateTime.utc_now())

    with [pubkey, "bsm", timestamp, ^request_path, signature] <- String.split(token, "|"),
         {:ok, signed_at, _} <- DateTime.from_iso8601(timestamp),
         true <- abs(DateTime.diff(now, signed_at)) <= max_skew || {:error, :stale},
         {:ok, key} <- PubKey.from_binary(pubkey, encoding: :hex),
         true <- Message.verify(signature, message(request_path, timestamp, body), key) do
      {:ok, pubkey}
    else
      {:error, :stale} -> {:error, :stale}
      _ -> {:error, :invalid}
    end
  end

  @doc """
  The compressed public key, hex, for a WIF. This is what Sigma calls the
  client's `accountPubkey`.
  """
  @spec pubkey(String.t()) :: String.t()
  def pubkey(wif), do: wif |> privkey_from_wif!() |> pubkey_hex()

  @doc """
  Encodes form fields exactly as JavaScript's `URLSearchParams#toString/0`.

  Sigma re-serializes the token request body that way before verifying the
  signature, so the body sent must be byte-identical to it. `URI.encode_query/1`
  differs on `~` and `*`.
  """
  @spec form_encode([{String.t(), String.t()}]) :: String.t()
  def form_encode(fields) do
    Enum.map_join(fields, "&", fn {key, value} ->
      form_escape(to_string(key)) <> "=" <> form_escape(to_string(value))
    end)
  end

  defp form_escape(string) do
    for <<byte <- string>>, into: "" do
      cond do
        byte == ?\s -> "+"
        byte in ?a..?z or byte in ?A..?Z or byte in ?0..?9 or byte in ~c"*-._" -> <<byte>>
        true -> "%" <> Base.encode16(<<byte>>)
      end
    end
  end

  defp message(request_path, timestamp, body) do
    "#{request_path}|#{timestamp}|#{body_hash(body)}"
  end

  defp body_hash(nil), do: ""
  defp body_hash(""), do: ""
  defp body_hash(body), do: :crypto.hash(:sha256, body) |> Base.encode16(case: :lower)

  # The member key only signs; Sigma knows it by its public key, which is the
  # same on either network. So accept a mainnet or testnet WIF whatever network
  # the host app runs BSV on (`PrivKey.from_wif!/1` follows that global setting,
  # and an app taking testnet payments would reject a mainnet member key).
  # The error never includes the value: it is a private key.
  defp privkey_from_wif!(wif) when is_binary(wif) do
    case B58.decode58_check(wif) do
      {:ok, {<<d::binary-32, 1>>, version}} when version in @wif_versions ->
        %PrivKey{d: d, compressed: true}

      {:ok, {<<d::binary-32>>, version}} when version in @wif_versions ->
        %PrivKey{d: d, compressed: false}

      _ ->
        raise ArgumentError, "the Sigma member key is not a mainnet or testnet WIF private key"
    end
  end

  defp privkey_from_wif!(_wif),
    do: raise(ArgumentError, "the Sigma member key is not set; expected a WIF string")

  defp pubkey_hex(privkey),
    do: privkey |> PubKey.from_privkey() |> PubKey.to_binary(encoding: :hex)

  defp now do
    DateTime.utc_now() |> DateTime.truncate(:millisecond) |> DateTime.to_iso8601()
  end
end
