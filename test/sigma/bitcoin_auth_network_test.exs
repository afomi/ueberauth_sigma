defmodule Sigma.BitcoinAuthNetworkTest do
  # Not async: these tests change the global :bsv network.
  use ExUnit.Case, async: false

  alias Sigma.BitcoinAuth

  @vectors "test/fixtures/bitcoin_auth_vectors.json" |> File.read!() |> Jason.decode!()

  @path "/api/auth/oauth2/token"

  # A host app may run BSV payments on testnet while its Sigma member key is a
  # mainnet WIF. The member key only ever signs, so the network must not matter.
  setup do
    previous = Application.get_env(:bsv, :network)
    Application.put_env(:bsv, :network, :test)

    on_exit(fn ->
      if previous,
        do: Application.put_env(:bsv, :network, previous),
        else: Application.delete_env(:bsv, :network)
    end)
  end

  test "a mainnet WIF still gives its public key when BSV runs on testnet" do
    assert BitcoinAuth.pubkey(@vectors["wif"]) == @vectors["pubkey"]
  end

  test "a mainnet WIF still signs byte-identical tokens when BSV runs on testnet" do
    assert BitcoinAuth.token(@vectors["wif"], @path, @vectors["body"], @vectors["timestamp"]) ==
             @vectors["bsm_token"]
  end

  test "the same key as a testnet WIF gives the same public key" do
    {:ok, {payload, <<0x80>>}} = B58.decode58_check(@vectors["wif"])
    testnet_wif = B58.encode58_check!(payload, <<0xEF>>)

    assert BitcoinAuth.pubkey(testnet_wif) == @vectors["pubkey"]
  end

  test "a value that is not a WIF raises without echoing it" do
    error = assert_raise ArgumentError, fn -> BitcoinAuth.pubkey("not-a-wif-secret") end
    refute error.message =~ "not-a-wif-secret"
  end
end
