defmodule Saml do
    @moduledoc """
    Verify consistency of SAML 1.0 requests.
    Then you need just to verify your signature - use verify_signature.
    Full verification is done by esaml Erlang library, but keep in mind that
    we don't verify SAML 1.0 assertions in it.
    """


    @doc """
    Verify that assertion was signed by certificate using Erlang native modules.
    Keep in mind that we don't verify digest for the assertion block.

        iex> assertion = File.read!("./test/assertion.txt")
        iex> Saml.verify(assertion)
        :ok
    """
    def verify(assertion) do
        xml = Base.decode64!(assertion, ignore: :whitespace, padding: false)
        {doc, []} =
            xml
            |> :binary.bin_to_list
            |> :xmerl_scan.string([quiet: true])

        :xmerl_dsig.verify(doc)
    end

end
