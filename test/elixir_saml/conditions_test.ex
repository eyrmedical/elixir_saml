defmodule ElixirSAML.ConditionsTest do
    use ExUnit.Case
    alias ElixirSAML
    alias ElixirSAML.Conditions

    setup_all do
      bankid_response = File.read!("test/assets/bankid") |> ElixirSAML.decode_response!

      %{ bankid_response: bankid_response }
    end

    test "Parse XML into Conditions struct", state do
      assert {:ok, conditions} = Conditions.parse(state.bankid_response)
      assert %Conditions{
        not_before: not_before,
        not_on_or_after: not_on_or_after,
        audience_restrictions: ["https://signicatdemo--Demo.cs8.my.salesforce.com"]
      } = conditions

      assert DateTime.to_string(not_before) == "2016-12-19 16:04:09.705Z"
      assert DateTime.to_string(not_on_or_after) == "2016-12-19 16:04:39.705Z"

    end

    test "Verify Condition date succeeds", state do
      {:ok, conditions} = Conditions.parse(state.bankid_response)

      test_datetime_override = %DateTime{
        calendar: Calendar.ISO,
        day: 19,
        hour: 16,
        microsecond: { 705000, 3 },
        minute: 4,
        month: 12,
        second: 14,
        std_offset: 0,
        time_zone: "Etc/UTC",
        utc_offset: 0, year: 2016, zone_abbr: "UTC"
      }
      assert {:ok, conditions} = Conditions.verify_date(conditions, test_datetime_override)
    end

    test "Verify Condition date fails when passing a later server time", state do
      {:ok, conditions} = Conditions.parse(state.bankid_response)
      assert {:error, "Server time is after the SAML NotBefore date."} = Conditions.verify_date(conditions)
    end

    test "Fail Condition date verification when passing an earlier server time", state do
      {:ok, conditions} = Conditions.parse(state.bankid_response)

      test_datetime_override = %DateTime{
        calendar: Calendar.ISO,
        day: 19,
        hour: 16,
        microsecond: { 705000, 3 },
        minute: 4,
        month: 12,
        second: 14,
        std_offset: 0,
        time_zone: "Etc/UTC",
        utc_offset: 0, year: 1970, zone_abbr: "UTC"
      }
      assert {:error, "Server time is before the SAML NotBefore date."} = Conditions.verify_date(conditions, test_datetime_override)
    end

    test "Check that a verification address is in the restricted audience condition", state do
      {:ok, conditions} = Conditions.parse(state.bankid_response)

      assert {:ok, _} = Conditions.verify_audience(conditions, "https://signicatdemo--Demo.cs8.my.salesforce.com")
    end

    test "Check that an invalid audience fails verification", state do
      {:ok, conditions} = Conditions.parse(state.bankid_response)

      assert {:error, _} = Conditions.verify_audience(conditions, "https://notvalid")
    end

end
