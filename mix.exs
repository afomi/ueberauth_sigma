defmodule UeberauthSigma.MixProject do
  use Mix.Project

  def project do
    [
      app: :ueberauth_sigma,
      version: "0.1.0",
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "Ueberauth strategy for Sigma Identity (auth.sigmaidentity.com).",
      source_url: "https://github.com/afomi/ueberauth_sigma",
      package: [
        licenses: ["Apache-2.0"],
        links: %{"GitHub" => "https://github.com/afomi/ueberauth_sigma"},
        files: ~w(lib mix.exs README.md CHANGELOG.md LICENSE)
      ]
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  defp deps do
    [
      {:ueberauth, "~> 0.10"},
      {:req, "~> 0.5"},
      {:jose, "~> 1.11"},
      {:bsv, "~> 2.1"},
      # Base58Check, used directly to decode the member WIF for either network.
      {:basefiftyeight, "~> 0.1"},
      {:plug, "~> 1.14"},
      {:jason, "~> 1.4"}
    ]
  end
end
