defmodule ElixirSAML.Adapters.Signicat.NorwegianBankID do
  @moduledoc """
  Wrapper for SAML 1.1 authorization to parse Signicat's Norwegian BankID assertion.
  """
  alias ElixirSAML.{Identity, InvalidResponse}
  import SweetXml, only: [xpath: 2, xpath: 3, sigil_x: 2]
  require Logger

  @typedoc "Result of verification check"
  @type result :: {:ok, %Identity{}} | {:error, %InvalidResponse{}}

  @doc """
  Verify BankID SAML response, check the assertions and retrieve user data.


  result = doc |> xpath(
  ~x"//matchups/matchup"l,
  name: ~x"./name/text()",
  winner: [
    ~x".//team/id[.=ancestor::matchup/@winner-id]/..",
    name: ~x"./name/text()"
  ]
  )
  assert result == [
  %{name: 'Match One', winner: %{name: 'Team One'}},
  %{name: 'Match Two', winner: %{name: 'Team Two'}},
  %{name: 'Match Three', winner: %{name: 'Team One'}}
  ]

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

      {:ok,
       %Identity{
         uid: extract(attribute_statement, "unique-id"),
         national_id: extract(attribute_statement, "national-id"),
         first_name: extract(attribute_statement, "firstname"),
         last_name: extract(attribute_statement, "lastname"),
         date_of_birth: extract(attribute_statement, "date-of-birth"),
         gender: extract(attribute_statement, "national-id") |> determine_gender,
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
end
