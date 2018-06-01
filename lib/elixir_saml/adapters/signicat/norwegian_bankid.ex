defmodule ElixirSAML.Adapters.Signicat.NorwegianBankID do
	@moduledoc """
	Wrapper for SAML 1.1 authorization to parse Signicat's Norwegian BankID response.
	"""
	alias SAML
	require Logger

	
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
end
