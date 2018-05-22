defmodule SAML.Conditions do
    import SweetXml
    @moduledoc """
    Extracts the SAML Conditions statement and provides helper functions to check the status.

    The SAML Conditions statement contains a time window in which the SAML response is to be
    considered valid, as well as a list of URIs that should accept the SAML response.

    Example:
    ```
    <Conditions NotBefore="2016-12-19T16:04:09.705Z" NotOnOrAfter="2016-12-19T16:04:39.705Z">
      <AudienceRestrictionCondition>
        <Audience>https://signicatdemo--Demo.cs8.my.salesforce.com</Audience>
      </AudienceRestrictionCondition>
    </Conditions>
    ```
    """
    defstruct \
        not_before: "",
        not_on_or_after: "",
        audiences: []

    @doc """
    Check that the status code is `Success`.
    """
    @spec check_status(String.t()) :: {atom(), String.t()}
    def check_status(xml) do
      with "samlp:Success" <-
            SAML.extract_string_value(xml, "//*[local-name()='StatusCode']/@Value")
      do
            {:ok, xml}
      else
        _ ->
          error = SAML.extract_string_value(xml, "//*[local-name()='StatusMessage']/text()")
          error = Regex.replace(~r/(urn:signicat:error:|;)/, error, ":")
                |> String.split(":", trim: true) 
          case error do
              ["usercancel", _]       -> {:cancel,  ""}
              ["bankid", _, code | _] -> {:bankid,  code}
              ["bankid" | _]          -> {:bankid,  ""}
              _                       -> {:generic, ""}
          end
        end
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
    Parses the Conditions statement into a %Conditions{} struct.

        Examples
        iex> assertion =
            "<Conditions NotBefore=\"2016-12-19T16:04:09.705Z\" NotOnOrAfter=\"2016-12-19T16:04:39.705Z\">
              <AudienceRestrictionCondition>
                <Audience>https://signicatdemo--Demo.cs8.my.salesforce.com</Audience>
              </AudienceRestrictionCondition>
            </Conditions>"
        iex> Conditions.parse(assertion)
        %{:ok, %Conditions{
            not_before: "2016-12-19T16:04:09.705Z",
            not_on_or_after: "2016-12-19T16:04:39.705Z",
            audiences: [] }}
    """
    def parse(xml) do
        with \
            not_before = xpath(xml, ~x"//*[local-name()='Conditions']/@NotBefore") |> to_string(),
            not_on_or_after = xpath(xml, ~x"//*[local-name()='Conditions']/@NotOnOrAfter") |> to_string()
        do
            result = %Conditions{
                not_before: not_before,
                not_on_or_after: not_on_or_after,
                audiences: []
            }
            
            {:ok, result}
        else
            _ -> {:error, "Could not parse Conditions statement"}
        end
    end
end