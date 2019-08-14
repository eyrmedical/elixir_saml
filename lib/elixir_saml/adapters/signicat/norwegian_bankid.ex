defmodule ElixirSAML.Adapters.Signicat.NorwegianBankID do
  @moduledoc """
  Wrapper for SAML 1.1 authorization to parse Signicat's Norwegian BankID assertion.
  """
  alias ElixirSAML.{Identity, InvalidResponse}
  import SweetXml, only: [xpath: 3, sigil_x: 2]
  require Logger

  @typedoc "Result of verification check"
  @type result :: {:ok, %Identity{}} | {:error, %InvalidResponse{}}

  @doc """
  Verify BankID SAML response, check the assertions and retrieve user data.
  """
  @spec parse_assertion(Tuple.t()) :: result
  def parse_assertion(saml) do
    with {:status, {:ok, _}} <- {:status, ElixirSAML.check_status_code(saml)} do
      attribute_statement =
        saml
        |> xpath(
          ~x"//AttributeStatement/Attribute"l,
          name: ~x"./@AttributeName"s,
          namespace: ~x"./@AttributeNamespace"s,
          value: ~x"./AttributeValue/text()"s
        )

      national_id = extract(attribute_statement, "national-id")
      date_of_birth = extract(attribute_statement, "date-of-birth")

      {:ok,
       %Identity{
         uid: extract(attribute_statement, "unique-id"),
         national_id: extract(attribute_statement, "national-id"),
         first_name: extract(attribute_statement, "firstname"),
         last_name: extract(attribute_statement, "lastname"),
         date_of_birth: determine_birthdate(national_id, date_of_birth),
         gender: determine_gender(national_id),
         origin: :norwegian_bankid
       }}
    else
      {:status, error} -> error
      _ -> {:error, "SAML processing caused an unexpected error"}
    end
  end

  defp extract(attribute_statement, attribute_name) do
    case Enum.filter(attribute_statement, &(&1.name == attribute_name)) do
      [attribute | _] -> attribute.value
      [] -> "not_found"
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

  @spec determine_birthdate(String.t(), String.t()) :: String.t()
  defp determine_birthdate(nor_national_id, fallback_birthdate) do
    case NorwegianIdNumber.parse(nor_national_id) do
      {:ok, %NorwegianIdNumber{
        birth_day: birth_day,
        birth_month: birth_month,
        birth_year: birth_year
      }} ->
        "#{birth_year}-#{zero_pad(birth_month, 2)}-#{zero_pad(birth_day, 2)}"
      _ ->
        fallback_birthdate
    end
  end

  @spec zero_pad(integer(), integer()) :: String.t
  defp zero_pad(number, length) when is_integer(number) and is_integer(length) do
    number
    |> Integer.to_string()
    |> String.pad_leading(length, "0")
  end
end
