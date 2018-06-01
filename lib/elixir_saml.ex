defmodule ElixirSAML do
  @moduledoc """
  Verify consistency of SAML 1.0 requests.
  Then you need just to verify your signature - use verify_signature.
  Full verification is done by esaml Erlang library, but keep in mind that
  we don't verify SAML 1.0 assertions in it.
  """
  import SweetXml
  alias ElixirSAML.{Conditions, Identity}
  import SweetXml, only: [xpath: 2, sigil_x: 2]

  @audience Application.get_env(:elixir_saml, :audience, nil)

  @typedoc "XML formatted string"
  @type xml :: String.t()

  @typedoc "XML AttributeName"
  @type attribute_name :: String.t()

  @typedoc "XML AttributeValue"
  @type attribute_value :: any()

  @typedoc "XML AttributeValue as string"
  @type attribute_string_value :: String.t()

  @typedoc "SAML Base64 encoded response"
  @type saml_base_64 :: String.t()

  @typedoc "Conditions dates"
  @type conditions_dates :: {atom(), %DateTime{}, %DateTime{}} | {atom(), String.t()}

  @typedoc "Current date"
  @type current_date :: %DateTime{}

  @typedoc "Authentication result"
  @type result :: {atom(), %Identity{}} | {atom(), String.t()}

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

  @spec verify(saml_base_64) :: result
  def verify(saml_base_64) do
    with {:ok, decoded_response} <- decode_response(saml_base_64),
         {:ok, saml_document} <- verify_signature(decoded_response),
         {:ok, saml_document} <- check_status_code(saml_document),
         {:ok, %Conditions{} = conditions} <- Conditions.parse(saml_document),
         {:ok, "Date check passed"} <- Conditions.verify_date(conditions),
         {:ok, %Conditions{}} <- Conditions.verify_audience(conditions, @audience) do
      {:ok, conditions}
    end
  end

  @doc """
  Verify that a SAML document was signed by certificate using Erlang native modules.
  Keep in mind that we don't verify digest for the assertion block.
  """
  @spec verify_signature(xml) :: {atom(), xml}
  def verify_signature(saml_document) do
    {doc, []} =
      saml_document
      |> :binary.bin_to_list()
      |> :xmerl_scan.string(quiet: true)

    {:xmerl_dsig.verify(doc), doc}
  end

  @spec verify_signature!(saml_base_64) :: atom()
  def verify_signature!(saml_document) do
    case verify_signature(saml_document) do
      {:ok, _doc} -> :ok
      _ -> :error
    end
  end

  @doc """
  Check that the status code is `Success`.
  """
  @spec check_status_code(String.t()) :: {atom(), String.t()}
  def check_status_code(xml) do
    with "samlp:Success" <- xpath(xml, ~x"//Status/@StatusCode/@Value") |> IO.inspect do
      {:ok, xml}
    else
      _ ->
        error = xpath(xml, ~x"//*[local-name()='StatusMessage']/text()")

        error =
          Regex.replace(~r/(urn:signicat:error:|;)/, error, ":")
          |> String.split(":", trim: true)

        case error do
          ["usercancel", _] -> {:cancel, ""}
          ["bankid", _, code | _] -> {:bankid, code}
          ["bankid" | _] -> {:bankid, ""}
          _ -> {:generic, ""}
        end
    end
  end

  @spec decode_response(saml_base_64) :: {atom(), xml}
  def decode_response(saml_response) do
    Base.decode64(saml_response, ignore: :whitespace, padding: false)
  end
end
