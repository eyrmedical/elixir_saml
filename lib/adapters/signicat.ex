defmodule NorwegianBankID do
	@moduledoc """
	Wrapper for SAML 1.1 authorization to parse Signicat's Norwegian BankID response.
	"""
	alias SAML
	require Logger

	defmodule UserData do
		@moduledoc false
		defstruct \
			uid: "",
			national_id: "",
			first_name: "",
			last_name: "",
			date_of_birth: "",
			gender: ""
	end

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

	@typedoc "SAML formatted XML string"
	@type xml :: String.t

	@typedoc "Base64 encoded SAML response"
	@type saml_response :: String.t

	@typedoc "Result of verification check"
	@type result :: {:ok, %NorwegianBankID.UserData{}} | {:error, %InvalidResponse{}}


	@doc """
	Verify BankID SAML response, check the assertions and retrieve user data.
	"""
	@spec verify(saml_response) :: result
	def verify(response) do
	  with \
			{:verify, {:ok, xml}} <- {:verify, SAML.verify(response)},
			%NorwegianBankID.UserData{} = user <- process_assertion(xml)
	  do
			{:ok, user}
	  else
			{:verify, _} ->
				{:error, InvalidResponse.invalid_signature()}
			{:error, message} ->
				{:error, InvalidResponse.exception(message: message)}
			error ->
				Logger.error(fn () ->
					"""
					BankID failed:
					#{inspect(error)}
					"""
				end)
				{:error, InvalidResponse.generic()}
	  end
	end
	def verify(_), do: {:error, InvalidResponse.generic()}

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
	Validate and extract user information from the SAML assertions block.
	"""
	def process_assertion(xml) do
		with {:ok, _} <- check_status(xml) do
			%UserData{
			  uid: SAML.extract_assertion_attribute_as_string(xml, "unique-id"),
			  national_id: SAML.extract_assertion_attribute_as_string(xml, "national-id"),
			  first_name: SAML.extract_assertion_attribute_as_string(xml, "firstname"),
			  last_name: SAML.extract_assertion_attribute_as_string(xml, "lastname"),
			  date_of_birth: SAML.extract_assertion_attribute_as_string(xml, "date-of-birth"),
			  gender: SAML.extract_assertion_attribute_as_string(xml, "national-id") |> determine_gender()
			}
		else
			{:cancel, _} -> {:error, "User cancelled authentication"}
			{:bankid, code} -> {:error, "BankID authenticaten caused an error: #{code}"}
			{:error, reason} -> {:error, reason}
			_ -> {:error, "SAML processing caused an unexpected error"}
		end
	end


  @spec determine_gender(String.t) :: String.t
  defp determine_gender(nor_national_id) do
    {charcode, _} = nor_national_id |> String.to_charlist |> List.pop_at(8)
    case [charcode] |> List.to_integer |> rem(2) do
      1 -> "male"
      0 -> "female"
    end
  end
  defp determine_gender(_), do: "unknown"
end
