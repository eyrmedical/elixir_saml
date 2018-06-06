defmodule ElixirSAMLTest do
  use ExUnit.Case
  alias ElixirSAML

  test "Check signature" do
    {:ok, bankid} = File.read("test/assets/bankid")

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

    assert {:ok, _} = ElixirSAML.verify(bankid, mock_server_time)
  end

  test "Check condition dates fails without overriding date" do
    {:ok, bankid} = File.read("test/assets/bankid")
    assert {:error, _saml_document} = ElixirSAML.verify(bankid)
  end
end
