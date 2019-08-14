# ElixirSAML

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed as:

  1. Add `elixir_saml` to your list of dependencies in `mix.exs`:

    ```elixir
    def deps do
      [{:elixir_saml, "~> 0.3"}]
    end
    ```

# About SAML

Security Assertion Markup Language (SAML) documents contains signed and verified information from an authentication and/or identity provider.

A SAML document consists of a _Signature_, a _Conditions Statement_, an _Assertion_ and some metadata about formatting, response status and errors.

This library provides utility modules to check conditions, verify signatures and return the parsed assertion as a struct: `%Identity{}`.
