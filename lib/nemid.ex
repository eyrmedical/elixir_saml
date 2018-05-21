defmodule NemId do
  @moduledoc """
  Wrapper for SAML 1.1 authorization to use Danish NemID.
  """

  import SweetXml

  @doc """
  Read SAML NemId settings.
  """
  def config(key, default \\ nil) do
    Keyword.get(Application.get_env(:saml, NemId), key, default)
  end

  @doc """
  Get URL to make NemID SAML requests.

    iex> NemId.url("https://localhost:4000/nemid/verify")
    NemId.config(:url) <> "https%3A%2F%2Flocalhost%3A4000%2Fnemid%2Fverify"

    iex> NemId.url("https://localhost:4000/nemid/verify", mobile: true)
    NemId.config(:mobile_url) <> "https%3A%2F%2Flocalhost%3A4000%2Fnemid%2Fverify"
  """
  @spec url(String.t, Keyword.t) :: String.t
  def url(callback_url, opts \\ []) do
    prefix = case Keyword.fetch(opts, :mobile) do
      {:ok, _} -> config(:mobile_url)
      _ -> config(:url)
    end

    prefix <> URI.encode(callback_url, &URI.char_unreserved?/1)
  end

  @doc """
  Verify NemId SAML response and check the assertions.
  """
  @spec verify(map()) :: {:ok, map()} | {:error, %NemId.InvalidResponse{}}
  def verify(%{"SAMLResponse" => response}) do
    case {Saml.verify(response), parse_assertions(response)}  do
      {:ok, %{
        uid: uid,
        national_id: national_id,
        firstname: firstname,
        lastname: lastname,
        date_of_birth: date_of_birth
      }} ->
        {:ok, %{
          uid: to_string(uid),
          national_id: to_string(national_id),
          firstname: to_string(firstname),
          lastname: to_string(lastname),
          date_of_birth: to_string(date_of_birth)
        }}
      {:ok, _} ->
        {:error, NemId.InvalidResponse.exception(message: "invalid assertions")}
      r ->
        IO.inspect(r)
        {:error, NemId.InvalidResponse.generic}
    end
  end
  def verify(_) do
    {:error, NemId.InvalidResponse.generic}
  end

  @doc """
  Extract user information from the SAML assertions block.
  """
  def parse_assertions(response) do
    xml = Base.decode64!(response, ignore: :whitespace, padding: false)
    %{
      uid: xml_assert_value(xml, "unique-id"),
      national_id: xml_assert_value(xml, "national-id"),
      firstname: xml_assert_value(xml, "firstname"),
      lastname: xml_assert_value(xml, "lastname"),
      date_of_birth: xml_assert_value(xml, "date-of-birth")
    }
  end

  @spec xml_assert_value(String.t, String.t) :: String.t
  defp xml_assert_value(xml, key) do
    xpath(xml, ~x"Assertion/AttributeStatement/Attribute[contains(@AttributeName,'#{key}')]/AttributeValue/text()")
  end


  defmodule InvalidResponse do
    @moduledoc """
    Exception raised with invalid SAML response.
    """
  
    defexception message: "invalid NemId SAML 1.1 response"

    def generic do
      exception(message: "invalid NemId SAML 1.1 response")
    end

    def exception(opts) do
      %InvalidResponse{message: Keyword.fetch!(opts, :message)}
    end
  end
end
