defmodule ElixirSAML.Adapters.Signicat.DanishNemID do
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

      {:ok,
       %Identity{
         uid: extract(attribute_statement, "unique-id"),
         national_id: national_id,
         first_name: extract(attribute_statement, "firstname"),
         last_name: extract(attribute_statement, "lastname"),
         date_of_birth: determine_birthdate(national_id),
         gender: determine_gender(national_id),
         origin: :danish_nemid
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
  def determine_gender(cpr_number) do
    {charcode, _} = cpr_number |> String.to_charlist() |> List.pop_at(9)

    case [charcode] |> List.to_integer() |> rem(2) do
      1 -> "male"
      0 -> "female"
    end
  end

  @doc """
  Determine full birth date from a Danish CPR number
  """

  def determine_birthdate("not_found"), do: "not_found"

  @spec determine_birthdate(String.t()) :: String.t()
  def determine_birthdate(
        <<dd::bytes-size(2)>> <>
          <<mm::bytes-size(2)>> <>
          <<yy::bytes-size(2)>> <> <<century_code::bytes-size(1)>> <> <<_rest::bytes-size(3)>>
      ) do
    century_code = String.to_integer(century_code)
    year = String.to_integer(yy)

    year = year(century_code, year)
    year <> "-" <> mm <> "-" <> dd
  end

  # 7th number in Danish CPR numbers is a "century_code" which will
  # calculate which century a year is in based on it's value combined
  # with what period the year is in:

  # |      |         Year          |
  # | Code | 00-36 | 37-57 | 58-99 |
  # | ---- | ----- | ----– | ----– |
  # | 0-3  | 1900  | 1900  | 1900  |
  # | 4    | 2000  | 1900  | 1900  |
  # | 5-8  | 2000  | 2000  | 1800  |
  # | 9    | 2000  | 1900  | 1900  |
  defp year(cc, yy) do
    century =
      case cc do
        cc when cc <= 3 -> "19"
        cc when cc in [4, 9] -> if yy > 36, do: "19", else: "20"
        _ -> if yy > 57, do: "18", else: "20"
      end

    # Add zero padding
    year = if yy < 10, do: "0#{yy}", else: "#{yy}"

    century <> year
  end
end
