vectors = "test/fixtures/bitcoin_auth_vectors.json" |> File.read!() |> Jason.decode!()

Application.put_env(:ueberauth, Ueberauth.Strategy.Sigma.OAuth,
  client_id: "qart-test",
  member_wif: vectors["wif"],
  req_options: [plug: {Req.Test, Ueberauth.Strategy.Sigma}]
)

ExUnit.start()
