defmodule ElixirSAMLTest do
  use ExUnit.Case
  alias ElixirSAML.{Identity}

  setup_all do
    bankid_mock_server_time = %DateTime{
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

    nemid_mock_server_time = %DateTime{
      calendar: Calendar.ISO,
      day: 22,
      hour: 10,
      microsecond: {971_000, 3},
      minute: 0,
      month: 5,
      second: 19,
      std_offset: 0,
      time_zone: "Etc/UTC",
      utc_offset: 0,
      year: 2018,
      zone_abbr: "UTC"
    }

    nemid_response = File.read!("test/assets/nemid")
    bankid_response = File.read!("test/assets/bankid")

    %{
      nemid_response: nemid_response,
      bankid_response: bankid_response,
      bankid_mock_server_time: bankid_mock_server_time,
      nemid_mock_server_time: nemid_mock_server_time
    }
  end

  test "Check signature", state do 
    assert {:ok, _} = ElixirSAML.verify(state.bankid_response, state.bankid_mock_server_time)
    assert {:ok, _} = ElixirSAML.verify(state.nemid_response, state.nemid_mock_server_time)
  end

  test "Check condition dates fails without overriding date", state do
    assert {:error, _saml_document} = ElixirSAML.verify(state.bankid_response)
  end

  test "Automatically detect and parse assertion for BankID", state do
    {:ok, saml_document} = ElixirSAML.verify(state.bankid_response, state.bankid_mock_server_time)
    assert {:ok, %Identity{}} = ElixirSAML.parse_assertion(saml_document)
  end

  test "Automatically detect and parse assertion for NemID", state do
    {:ok, saml_document} = ElixirSAML.verify(state.nemid_response, state.nemid_mock_server_time)
    assert {:ok, %Identity{}} = ElixirSAML.parse_assertion(saml_document)
  end
end
