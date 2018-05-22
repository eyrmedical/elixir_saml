defmodule ElixirSAML.Mixfile do
    use Mix.Project

    def project do
        [app: :elixir_saml,
         version: "0.1.8",
         elixir: "~> 1.4",
         build_embedded: Mix.env == :prod,
         start_permanent: Mix.env == :prod,
         deps: deps()]
    end

    # Configuration for the OTP application
    #
    # Type "mix help compile.app" for more information
    def application do
        [applications: [:logger]]
    end

    defp deps do
        [
            {:sweet_xml, "~> 0.6.5"},
            {:esaml, github: "eyrmedical/esaml"},
            {:ex_doc, "~> 0.16", only: :dev, runtime: false}
        ]
    end
end
