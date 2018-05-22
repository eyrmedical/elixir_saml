defmodule SAMLTest do
    use ExUnit.Case
    doctest SAML

    setup_all do
      "SAMLResponse:" <> response = File.read!("./test/assets/bankid_response.txt")
      "SAMLResponse:" <> error_response = File.read!("./test/assets/bankid_error_response.txt")
       %{ response: response, 
          error_response: error_response, 
          test_datetime_override: %DateTime{
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
      }
    end

    test "Check signature", state do
      assert {:ok, _} = SAML.verify(state.response)
    end

    test "Check condition dates succeeds", state do
      {:ok, xml} = SAML.verify(state.response)
      assert {:ok, _} = xml
        |> SAML.extract_condition_dates()
        |> SAML.compare_condition_dates(state.test_datetime_override)
    end

    test "Check condition dates fails", state do
      {:ok, xml} = SAML.verify(state.response)
      assert {:error, _} = xml
        |> SAML.extract_condition_dates()
        |> SAML.compare_condition_dates()
    end
end
