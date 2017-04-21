defmodule BankId do
    @moduledoc """
    Wrapper for SAML 1.1 authorization to use Norwegian bank id.
    """

    import SweetXml
    @env Mix.env

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
                date_of_birth: date_of_birth,
                gender: gender
            }}} ->
                {:ok, %{
                    uid: uid |> to_string,
                    national_id: national_id |> to_string,
                    firstname: firstname |> to_string,
                    lastname: lastname |> to_string,
                    date_of_birth: date_of_birth |> to_string,
                    gender: gender |> to_string
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

        error_message = "If you see this error it probably means that your server time has driftet. This can happen with Docker containers while your computer is sleeping. Restart your Docker containers and try again."

        case {not_before, not_on_or_after} do
            {:gt, :lt} -> {:ok, "Date check passed"}
            {:lt, _} -> {:error, "Current date is before the NotBefore date in the SAML assertion.\n" <> error_message}
            {_, :gt} -> {:error, "Current date is after the NotBefore date in the SAML assertion.\n" <> error_message}
            {_, :eq} -> {:error, "Current date is equal to the NotOnOrAfter date in the SAML assertion.\n"  <> error_message}
            _ -> {:error, "Invalid dates passed to SAML Conditions"}
        end
    end

    defp compare_date(date) do
      # Add a recommended offset of 5 seconds
      now =
        case Mix.env do
          :test -> %DateTime{
             calendar: Calendar.ISO, day: 19, hour: 16, microsecond: {705000, 3},
             minute: 4, month: 12, second: 19, std_offset: 0, time_zone: "Etc/UTC",
             utc_offset: 0, year: 2016, zone_abbr: "UTC"
            }
          _ -> DateTime.utc_now()
        end




      case date do
        {:ok, date, _} -> now |> Map.put(:second, now.second + 5) |> DateTime.compare(date)
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
            date_of_birth: xml_assert_value(xml, "date-of-birth"),
            gender: xml_assert_value(xml, "national-id") |> determine_gender()
        }
    end

    @spec determine_gender(String.t) :: String.t
    defp determine_gender(nor_national_id) do
      {charcode, _} = List.pop_at(nor_national_id, 8)
      case [charcode] |> List.to_integer |> rem(2) do
        1 -> "male"
        0 -> "female"
      end
    end
    defp determine_gender(_), do: "unknown"

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
