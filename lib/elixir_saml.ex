defmodule ElixirSAML do
  @moduledoc """
  Verify consistency of SAML 1.0 requests.
  Then you need just to verify your signature - use verify_signature.
  Full verification is done by esaml Erlang library, but keep in mind that
  we don't verify SAML 1.0 assertions in it.
  """
  import SweetXml
  require Logger

  @latency_compensation Application.get_env(:elixir_saml, :latency_compensation, 0)
  #@env Mix.env()

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

  @typedoc "SweeXML path sigil `~xpath`"
  @type path :: any()

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


  @doc """
  Verify that assertion was signed by certificate using Erlang native modules.
  Keep in mind that we don't verify digest for the assertion block.
  
    Examples
    iex> assertion = File.read!("./test/assets/assertion.txt")
    iex> SAML.verify!(assertion)
    :ok
  """
  @spec verify_signature(saml_base_64) :: {atom(), xml}
  def verify_signature(assertion) do
    {doc, []} =
      decode_response!(assertion)
      |> :binary.bin_to_list
      |> :xmerl_scan.string([quiet: true])

    {:xmerl_dsig.verify(doc), doc}
  end

  @spec verify_signature!(saml_base_64) :: atom()
  def verify_signature!(assertion) do
    case verify_signature(assertion) do
      {:ok, _doc} -> :ok
      _ -> :error
    end
  end
  
  @spec decode_response(saml_base_64) :: {atom(), xml}
  defp decode_response(saml_response) do
    Base.decode64(saml_response, ignore: :whitespace, padding: false)
  end

  @spec decode_response!(saml_base_64) :: xml
  defp decode_response!(saml_response) do
    case decode_response(saml_response) do
      {:ok, xml} -> xml
      _ -> :error
    end
  end


  @doc """
  Extracts Assertion Attributes from SAML document.
  """
  @spec extract_assertion_attribute(xml, attribute_name) :: attribute_value
  def extract_assertion_attribute(xml, attribute_name) do
    xpath(xml, ~x"Assertion/AttributeStatement/Attribute[contains(@AttributeName,'#{attribute_name}')]/AttributeValue/text()")
  end
  @spec extract_assertion_attribute_as_string(xml, attribute_name) :: attribute_string_value
  def extract_assertion_attribute_as_string(xml, attribute_name) do
    extract_assertion_attribute(xml, attribute_name)
    |> to_string()
  end


  @doc """
  Extract SAML value from XML path.
  """
  @spec extract_value(xml, path) :: any()
  def extract_value(xml, path) do
    xpath(xml, string_to_path(path))
  end

    @doc """
  Extract SAML value from XML path.
  """
  @spec extract_value(xml, path) :: any()
  def extract_string_value(xml, path) do
    extract_value(xml, path) |> to_string()
  end

  @spec string_to_path(String.t()) :: path
  defp string_to_path(string) do 
    ~x"#{string}"
  end
end