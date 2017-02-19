defmodule BankId do
    @moduledoc """
    Wrapper for SAML 1.1 authorization to use Norwegian bank id.
    """

    import SweetXml

    @doc """
    Get URL to make BankId SAML requests.

        iex> BankId.url("https://localhost:4000/bankid/verify")
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

        IO.puts "Veifying SAML response"

        case {Saml.verify(response), process_assertion(response)} do

            {:ok, {:ok, %{
                uid: uid,
                national_id: national_id,
                firstname: firstname,
                lastname: lastname,
                date_of_birth: date_of_birth
            }}} ->
                {:ok, %{
                    uid: uid |> to_string,
                    national_id: national_id |> to_string,
                    firstname: firstname |> to_string,
                    lastname: lastname |> to_string,
                    date_of_birth: date_of_birth |> to_string
                }}

            {:ok, {:error, message}} ->
                {:error, BankId.InvalidResponse.exception(message: message)}

            {:ok, _} ->
                {:error, BankId.InvalidResponse.exception(message: "invalid assertions")}

            _ ->
                {:error, BankId.InvalidResponse.generic}
        end
    end
    def verify(_) do
        {:error, BankId.InvalidResponse.generic}
    end

    @doc """
    Check that the status code is `Success`.
    """
    def check_status(xml) do
        case xpath(xml, ~x"//*[local-name()='StatusCode']/@Value") |> to_string do
            "samlp:Success" -> {:ok, :nil}
            _ -> extract_error_message(xml)
        end
    end

    defp extract_error_message(xml) do
        error = xpath(xml, ~x"//*[local-name()='StatusMessage']/text()")
                |> to_string

        error = Regex.replace(~r/(urn:signicat:error:|;)/, error, ":")
                |> String.split(":", trim: true)

        case error do
            ["usercancel", _]       -> {:cancel,  :nil}
            ["bankid", _, code | _] -> {:bankid,  code}
            ["bankid" | _]          -> {:bankid,  :nil}
            _                       -> {:generic, :nil}
        end
    end

    @doc """
    Check that current date is within `<Conditions NotBefore="date" NotOnOrAfter="date" />`.
    """
    def check_condition_dates(response) do
        xml = Base.decode64!(response, ignore: :whitespace, padding: false)

        not_before =
            xpath(xml, ~x"//*[local-name()='Conditions']/@NotBefore")
            |> to_string
            |> DateTime.from_iso8601
            |> compare_date

        not_on_or_after =
            xpath(xml, ~x"//*[local-name()='Conditions']/@NotOnOrAfter")
            |> to_string
            |> DateTime.from_iso8601
            |> compare_date

        case {not_before, not_on_or_after} do
            # {:gt, :gt} -> {:ok, "TEST ONLY: Fake date check passed"}

            {:gt, :lt} -> {:ok, "Date check passed"}
            {:lt, _} -> {:error, "Current date is before NotBefore date"}
            {_, :gt} -> {:error, "Current date is after NotOnOrAfter date"}
            {_, :eq} -> {:error, "Current date is on NotOnOrAfter date"}
            _ -> {:error, "Invalid dates passed to SAML Conditions"}
        end
    end

    defp compare_date(date) do
       case date do
            {:ok, date, _} -> DateTime.compare(DateTime.utc_now(), date)
            _ -> :err
        end
    end

    @doc """
    Validate and extract user information from the SAML assertions block.
    """
    def process_assertion(response) do
        xml = Base.decode64!(response, ignore: :whitespace, padding: false)

        initial_check = 
            case check_status(xml) do
                {:ok, _} -> check_condition_dates(response)
                error -> error
            end

        case initial_check do
            {:ok, _} -> {:ok, parse_attributes(xml)}
            {:cancel, _} -> {:error, "User cancelled authentication"}
            {:bankid, code} -> {:error, "BankID authenticaten caused an error: #{code}"}
            {:error, reason} -> {:error, reason}
            _ -> {:error, "SAML processing caused an unexpected error"}
        end
    end

    @spec parse_attributes(String.t) :: String.t
    defp parse_attributes(xml) do
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
        Exception raised with invalid SAML response.me
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