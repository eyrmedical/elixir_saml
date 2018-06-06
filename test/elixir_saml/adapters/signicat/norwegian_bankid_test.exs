defmodule NorwegianBankIDTest do
  use ExUnit.Case
  alias ElixirSAML.{Identity}
  alias ElixirSAML.Adapters.Signicat.NorwegianBankID

  setup_all do
    {:ok, bankid_base_64} = File.read("test/assets/bankid")

    mock_server_time = %DateTime{
      calendar: Calendar.ISO,
      day: 19,
      hour: 16,
      microsecond: {705_000, 3},
      minute: 4,
      month: 12,
      second: 14,
      std_offset: 0,
      time_zone: "Etc/UTC",
      utc_offset: 0,
      year: 2016,
      zone_abbr: "UTC"
    }

    %{bankid_base_64: bankid_base_64, mock_server_time: mock_server_time}
  end

  test "Example of a valid SAML authorization check", state do
    assert {:ok, saml_document} = ElixirSAML.verify(state.bankid_base_64, state.mock_server_time)

    assert {:ok,
            %Identity{
              date_of_birth: "1980-01-01",
              first_name: "Test",
              gender: "male",
              last_name: "Pasient",
              national_id: "01018037731",
              origin: :norwegian_bankid,
              uid: "9578-6000-4-129724"
            }} = NorwegianBankID.parse_assertion(saml_document)
  end
end
