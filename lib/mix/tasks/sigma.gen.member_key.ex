defmodule Mix.Tasks.Sigma.Gen.MemberKey do
  @shortdoc "Prints a new Sigma client member key (WIF and public key)"

  @moduledoc """
  Prints a new secp256k1 key for one Sigma OAuth client.

      mix sigma.gen.member_key

  Register the public key as the client's `accountPubkey` at
  https://auth.sigmaidentity.com, and put the WIF in that deploy's secrets as
  `SIGMA_MEMBER_WIF`. Make one key per client (per app and environment).
  Nothing is written to disk.
  """

  use Mix.Task

  @impl true
  def run(_args) do
    wif = BSV.PrivKey.new() |> BSV.PrivKey.to_wif()

    Mix.shell().info("""
    accountPubkey:    #{Sigma.BitcoinAuth.pubkey(wif)}
    SIGMA_MEMBER_WIF: #{wif}
    """)
  end
end
