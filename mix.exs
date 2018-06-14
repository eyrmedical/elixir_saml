defmodule ElixirSAML.Mixfile do
  use Mix.Project

  def project do
    [
      app: :elixir_saml,
      version: "0.3.2",
      elixir: "~> 1.4",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Configuration for the OTP application
  #
  # Type "mix help compile.app" for more information
  def application do
    [applications: [:logger]]
  end

  # Dependencies can be Hex packages:
  #
  #     {:mydep, "~> 0.3.0"}
  #
  # Or git/path repositories:
  #
  #     {:mydep, git: "https://github.com/elixir-lang/mydep.git", tag: "0.1.3"}
  #
  # Type "mix help deps" for more examples and options
  defp deps do
    [
      {:sweet_xml, "~> 0.6.5"},
      {:esaml, github: "eyrmedical/esaml"},
      {:ex_doc, "~> 0.16", only: :dev, runtime: false}
    ]
  end
end
