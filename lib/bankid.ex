defmodule BankId do
    @moduledoc """
    Wrapper for SAML 1.1 authorization to use Norwegian bank id.
    """

    import SweetXml

    @doc """
    Get URL to make BankId SAML requests.

        iex> generated_url = BankId.url("https://localhost:4000/bankid/verify")
        Application.get_env(:bankid, :url) <> "https%3A%2F%2Flocalhost%3A4000%2Fbankid%2Fverify"

        iex> BankId.url("https://localhost:4000/bankid/verify", mobile: true)
        Application.get_env(:bankid, :mobile_url) <> "https%3A%2F%2Flocalhost%3A4000%2Fbankid%2Fverify"
    """
    @spec url(String.t, Keyword.t) :: String.t
    def url(callback_url, opts \\ []) do
        prefix = case Keyword.fetch(opts, :mobile) do
            {:ok, _} -> Application.get_env(:bankid, :mobile_url)
            _ -> Application.get_env(:bankid, :url)
        end

        prefix <> URI.encode(callback_url, &URI.char_unreserved?/1)
    end

    @doc """
    Verify BankId SAML response and check the assertions.
    """
    @spec verify(map()) :: {:ok, map()} | {:error, %BankId.InvalidResponse{}}
    def verify(%{"SAMLResponse" => response}) do
        case {Saml.verify(response), parse_assertions(response)}  do
            {:ok, %{
                uid: uid,
                national_id: national_id,
                firstname: _,
                lastname: _,
                date_of_birth: _
            } = data} ->
                {:ok, %{
                    uid: to_string(uid),
                    national_id: to_string(national_id),
                    firstname: to_string(firstname),
                    lastname: to_string(lastname),
                    date_of_birth: to_string(date_of_birth)
                }}
            {:ok, _} ->
                {:error, BankId.InvalidResponse.exception(message: "invalid assertions")}
            r ->
                IO.inspect(r)
                {:error, BankId.InvalidResponse.generic}
        end
    end
    def verify(_) do
        {:error, BankId.InvalidResponse.generic}
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
    
        defexception message: "invalid BankId SAML 1.1 response"

        def generic do
            exception(message: "invalid BankId SAML 1.1 response")
        end

        def exception(opts) do
            %InvalidResponse{message: Keyword.fetch!(opts, :message)}
        end
    end
end
