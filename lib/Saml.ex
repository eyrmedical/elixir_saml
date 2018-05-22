defmodule SAML do
    @moduledoc """
    Verify consistency of SAML 1.0 requests.
    Then you need just to verify your signature - use verify_signature.
    Full verification is done by esaml Erlang library, but keep in mind that
    we don't verify SAML 1.0 assertions in it.
    """
    import SweetXml
    require Logger

    @latency_compensation Application.get_env(:elixir_saml, :latency_compensation, 0)
    @env Mix.env()

    @typedoc "XML formatted string"
    @type xml :: String.t()

    @typedoc "XML AttributeName"
    @type attribute_name :: String.t()

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
    Decodes SAML assertion from Base64
    """
    @spec decode(saml_base_64) :: {atom(), xml}
    def decode(saml_response) do
        Base.decode64(saml_response, ignore: :whitespace, padding: false)
    end

    @spec decode!(saml_base_64) :: xml
    def decode!(saml_response) do
        case decode(saml_response) do
            {:ok, xml} -> xml
            _ -> :error
        end
    end


    @doc """
    Extracts Assertion Attributes from SAML document.
    """
    @spec extract_assertion_attribute_as_string(xml, attribute_name) :: attribute_string_value
    def extract_assertion_attribute_as_string(xml, attribute_name) do
        extract_assertion_attribute(xml, attribute_name)
        |> to_string()
    end

    @doc """
    Extracts Condition statement from SAML document.
    """
    @spec extract_condition(xml, attribute_name) :: attribute_string_value
    def extract_condition(xml, attribute_name) do
        xpath(xml, ~x"//*[local-name()='Conditions']/@#{attribute_name}")
        |> to_string
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

    @doc """
    Extract dates from Condition statement from SAML document
    """
    @spec extract_condition_dates(xml) :: conditions_dates
    def extract_condition_dates(xml) do
        with {:ok, %DateTime{} = not_before, _} =
                extract_condition(xml, "NotBefore")
                |> DateTime.from_iso8601(),
            {:ok, %DateTime{} = not_on_or_after, _} =
                extract_condition(xml, "NotOnOrAfter")
                |> DateTime.from_iso8601()
        do
            {:ok, not_before, not_on_or_after}
        else
            _ -> {:error, "Could not find condition dates in SAML document"}
        end
    end 

    @doc """
    Check that current date is within `<Conditions NotBefore="date" NotOnOrAfter="date" />`.

    Set `latency_compensation: 5` in config to set the recommended 5 seconds.
    """
    @spec compare_condition_dates(conditions_dates, current_date) :: {atom(), String.t()}
    def compare_condition_dates({:ok, not_before, not_on_or_after}, now \\ DateTime.utc_now()) do
        
        # Adds the recommended latency compensation (5 seconds)
        now = Map.put(now, :seconds, now.second + @latency_compensation)

        result = case {DateTime.compare(now, not_before), DateTime.compare(now, not_on_or_after)} do
            {:gt, :lt} ->
                {:ok, "Date check passed"}
            {:lt, _} ->
                {:error, "Server time is before the SAML NotBefore date."}
            {_, :gt} ->
                {:error, "Server time is after the SAML NotBefore date."}
            {_, :eq} ->
                {:error, "Server time is equal to the SAML NotOnOrAfter."}
            _ ->
                {:error, "Invalid dates passed to SAML Conditions"}
        end

        if elem(result, 0) === :error do
            Logger.error fn () -> """

                #{elem(result, 1)}

                SAML not before:         #{DateTime.to_string(not_before)}
                Server time:             #{DateTime.to_string(now)}
                SAML not on or after:    #{DateTime.to_string(not_on_or_after)}
                
                The SAML response timestamp is inconsistent with server time.

                If you see this error in production you should lax the latency
                compensation in config, although it is recommended to keep it at
                5 seconds or lower.

                If you see this error in development the most common cause is that
                the time of your docker container has drifted, which can happen if
                your computer has been suspended since you started the container.
                """
            end
        end

        result
    end

    @spec string_to_path(String.t()) :: path
    defp string_to_path(string) do 
        ~x"#{string}"
    end
end
