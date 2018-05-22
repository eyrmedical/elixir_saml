defmodule SAML.Provider.NorwegianBankID do
    @moduledoc """
    Extract user data from SAML conditions into a structured response
    """

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