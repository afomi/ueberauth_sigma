defmodule Sigma.BitcoinAuthTest do
  use ExUnit.Case, async: true

  alias Sigma.BitcoinAuth

  # Made by the npm packages bitcoin-auth@0.0.8 and @bsv/sdk@2.8.11 with
  # test/fixtures/bitcoin_auth_vectors.mjs.
  @vectors "test/fixtures/bitcoin_auth_vectors.json" |> File.read!() |> Jason.decode!()

  @path "/api/auth/oauth2/token"

  test "the public key matches @bsv/sdk's" do
    assert BitcoinAuth.pubkey(@vectors["wif"]) == @vectors["pubkey"]
  end

  test "form fields encode exactly as URLSearchParams" do
    fields = Enum.map(@vectors["fields"], &List.to_tuple/1)
    assert BitcoinAuth.form_encode(fields) == @vectors["body"]
  end

  test "a bsm token over a body is byte-identical to bitcoin-auth's" do
    assert BitcoinAuth.token(@vectors["wif"], @path, @vectors["body"], @vectors["timestamp"]) ==
             @vectors["bsm_token"]
  end

  test "a bsm token with no body is byte-identical to bitcoin-auth's" do
    assert BitcoinAuth.token(@vectors["wif"], @path, nil, @vectors["timestamp"]) ==
             @vectors["bsm_token_no_body"]
  end

  describe "verify/4" do
    setup do
      {:ok, now: DateTime.from_iso8601(@vectors["timestamp"]) |> elem(1)}
    end

    test "accepts bitcoin-auth's token and returns its key", %{now: now} do
      assert BitcoinAuth.verify(@vectors["bsm_token"], @path, @vectors["body"], now: now) ==
               {:ok, @vectors["pubkey"]}
    end

    test "refuses a changed body", %{now: now} do
      assert BitcoinAuth.verify(@vectors["bsm_token"], @path, @vectors["body"] <> "x", now: now) ==
               {:error, :invalid}
    end

    test "refuses another path", %{now: now} do
      assert BitcoinAuth.verify(@vectors["bsm_token"], "/other", @vectors["body"], now: now) ==
               {:error, :invalid}
    end

    test "refuses a token older than the allowed skew", %{now: now} do
      later = DateTime.add(now, 301)

      assert BitcoinAuth.verify(@vectors["bsm_token"], @path, @vectors["body"], now: later) ==
               {:error, :stale}
    end

    test "refuses the brc77 scheme, which is not implemented", %{now: now} do
      assert BitcoinAuth.verify(@vectors["brc77_token"], @path, @vectors["body"], now: now) ==
               {:error, :invalid}
    end

    test "accepts a token made just now" do
      token = BitcoinAuth.token(@vectors["wif"], @path, "a=1")
      assert BitcoinAuth.verify(token, @path, "a=1") == {:ok, @vectors["pubkey"]}
    end
  end
end
