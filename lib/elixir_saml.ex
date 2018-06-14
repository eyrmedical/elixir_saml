defmodule ElixirSAML do
  @moduledoc """
  Verify consistency of SAML 1.0 requests.
  Then you need just to verify your signature - use verify_signature.
  Full verification is done by esaml Erlang library, but keep in mind that
  we don't verify SAML 1.0 assertions in it.
  """
  import SweetXml
  alias ElixirSAML.{Conditions, Identity, Adapters}
  import SweetXml, only: [xpath: 2, sigil_x: 2]

  @typedoc "SAML Base64 encoded response"
  @type saml_base_64 :: String.t()

  @typedoc "Authentication result"
  @type result :: {atom()} | {atom(), String.t()}

  defmodule InvalidResponse do
    @moduledoc """
    Exception raised with invalid SAML response.
    """
    defexception message: "Invalid SAML 1.1 response"

    def generic do
      exception(message: "Invalid SAML 1.1 response")
    end

    def invalid_signature do
      exception(message: "Invalid SAML signature")
    end

    def exception(opts) do
      %InvalidResponse{message: Keyword.fetch!(opts, :message)}
    end
  end

  @spec verify(saml_base_64, %DateTime{}) :: result
  def verify(saml_base_64, server_time \\ DateTime.utc_now()) do
    with {:ok, saml_document} <- ElixirSAML.verify_document(saml_base_64),
         {:ok, %Conditions{}} <- Conditions.verify(saml_document, server_time) do
      {:ok, saml_document}
    else
      {:error, %InvalidResponse{message: message}} ->
        {:error, message}

      {:error, error} when is_bitstring(error) ->
        {:error, error}

      _ ->
        {:error, "Failed to parse or verify SAML Response"}
    end
  end

  @spec verify_document(saml_base_64) :: result
  def verify_document(saml_base_64) do
    with {:ok, saml_document} <- parse_document(saml_base_64),
         {:ok, saml_document} <- verify_signature(saml_document),
         {:ok, saml_document} <- check_status_code(saml_document) do
      {:ok, saml_document}
    end
  end

  @doc """
  Automatically detect adapter and parse a SAML assertion
  """
  def parse_assertion(saml_document) do
    case xpath(saml_document, ~x"//AuthenticationStatement/@AuthenticationMethod"s) do
      "urn:signicat:names:SAML:2.0:ac:BankID-NO-mobile" ->
        Adapters.Signicat.NorwegianBankID.parse_assertion(saml_document)

      "urn:signicat:names:SAML:2.0:ac:BankID-NO" ->
        Adapters.Signicat.NorwegianBankID.parse_assertion(saml_document)

      "urn:ksi:names:SAML:2.0:ac:BankID-NO" ->
        Adapters.Signicat.NorwegianBankID.parse_assertion(saml_document)

      "urn:ksi:names:SAML:2.0:ac:OCES" ->
        Adapters.Signicat.DanishNemID.parse_assertion(saml_document)

      _ ->
        {:error, "No adapters found for this SAML document"}
    end
  end

  @doc """
  Parse a 64-bit SAML response into a `:xmerl` document
  """
  @spec parse_document(saml_base_64) :: result
  def parse_document(saml_base_64) do
    with {:ok, decoded_response} <-
           Base.decode64(saml_base_64, ignore: :whitespace, padding: false),
         {doc, []} <-
           decoded_response
           |> :binary.bin_to_list()
           |> :xmerl_scan.string(quiet: true) do
      {:ok, doc}
    else
      _ ->
        {:error, "Failed to parse SAML document"}
    end
  end

  @doc """
  Verify that a SAML document was signed by certificate using Erlang native modules.
  Keep in mind that we don't verify digest for the assertion block.
  """
  def verify_signature(document) do
    {:xmerl_dsig.verify(document), document}
  end

  def verify_signature!(document) do
    :xmerl_dsig.verify(document)
  end

  @doc """
  Check that the status code is `Success`.
  """
  @spec check_status_code(String.t()) :: {atom(), String.t()}
  def check_status_code(saml) do
    case xpath(saml, ~x"//Status/StatusCode/@Value"s) do
      "samlp:Success" -> {:ok, saml}
      "samlp:Responder" -> {:error, extract_status_error(saml)}
      _ -> {:error, "SAML Status code check failed"}
    end
  end

  defp extract_status_error(saml) do
    xpath(saml, ~x"//Status/StatusMessage/text()"s)
  end
end
