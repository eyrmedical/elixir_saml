defmodule ElixirSAML.Adapters.Signicat.NorwegianBankID do
  @moduledoc """
  Wrapper for SAML 1.1 authorization to parse Signicat's Norwegian BankID assertion.
  """
  alias ElixirSAML.{Identity, InvalidResponse}
  import SweetXml, only: [xpath: 2, sigil_x: 2]
  require Logger

  @typedoc "SAML formatted XML string"
  @type xml :: String.t()

  @typedoc "Result of verification check"
  @type result :: {:ok, %Identity{}} | {:error, %InvalidResponse{}}

  @doc """
  Verify BankID SAML response, check the assertions and retrieve user data.
  """
  @spec parse_assertion(xml) :: result
  def parse_assertion(xml) do
    with {:ok, _} <- ElixirSAML.check_status(xml) do
      %ElixirSAML.Identity{
        # ~x"//Conditions/@NotBefore"
        uid: xpath(xml, ~x"//AttributeStatement/unique-id"),
        national_id: xpath(xml, ~x"//AttributeStatement/national-id"),
        first_name: xpath(xml, ~x"//AttributeStatement/firstname"),
        last_name: xpath(xml, ~x"//AttributeStatement/lastname"),
        date_of_birth: xpath(xml, ~x"//AttributeStatement/date-of-birth"),
        gender: xpath(xml, ~x"//AttributeStatement/national-id") |> determine_gender
      }
    else
      {:cancel, _} -> {:error, "User cancelled authentication"}
      {:bankid, code} -> {:error, "BankID authenticaten caused an error: #{code}"}
      {:error, reason} -> {:error, reason}
      _ -> {:error, "SAML processing caused an unexpected error"}
    end
  end

  @spec determine_gender(String.t()) :: String.t()
  defp determine_gender(nor_national_id) do
    {charcode, _} = nor_national_id |> String.to_charlist() |> List.pop_at(8)

    case [charcode] |> List.to_integer() |> rem(2) do
      1 -> "male"
      0 -> "female"
    end
  end
end
