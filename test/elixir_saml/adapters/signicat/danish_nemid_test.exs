defmodule DanishNemIDTest do
  use ExUnit.Case
  alias ElixirSAML.{Identity}
  alias ElixirSAML.Adapters.Signicat.DanishNemID

  setup_all do
    {:ok, nemid_base_64} = File.read("test/assets/nemid")

    mock_server_time = %DateTime{
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

    %{nemid_base_64: nemid_base_64, mock_server_time: mock_server_time}
  end

  test "Example of a valid SAML authorization check", state do
    assert {:ok, saml_document} = ElixirSAML.verify(state.nemid_base_64, state.mock_server_time)

    assert {:ok,
            %Identity{
              date_of_birth: "1958-07-07",
              first_name: "Theodora",
              gender: "female",
              last_name: "Mathiesen",
              national_id: "0707580210",
              origin: :danish_nemid,
              uid: "9208-2002-2-963154826612"
            }} = DanishNemID.parse_assertion(saml_document)
  end

  test "Determine gender from CPR number" do
    assert DanishNemID.determine_gender("0000000000") == "female"
    assert DanishNemID.determine_gender("0000000001") == "male"
    assert DanishNemID.determine_gender("0707580210") == "female"
  end

  test "Determine birthdate from CPR number" do
    assert DanishNemID.determine_birthdate("0707580210") == "1958-07-07"
    assert DanishNemID.determine_birthdate("0101000210") == "1900-01-01"
    assert DanishNemID.determine_birthdate("0101004210") == "2000-01-01"
    assert DanishNemID.determine_birthdate("0101586210") == "1858-01-01"
    assert DanishNemID.determine_birthdate("0101584210") == "1958-01-01"
    assert DanishNemID.determine_birthdate("0101374210") == "1937-01-01"
    assert DanishNemID.determine_birthdate("0101364210") == "2036-01-01"
  end
end
