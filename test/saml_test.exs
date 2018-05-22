defmodule SAMLTest do
    use ExUnit.Case
    doctest SAML

    setup_all do
      nemid_xml_response = File.read!("test/assets/NemID_samlResponse.xml")
      bankid_xml_response = File.read!("test/assets/BankID_samlResponse.xml")
      nemid_base64_response = File.read!("test/assets/nemid_base64.txt")
      "SAMLResponse:" <> bankid_base64_response = File.read!("test/assets/bankid_base64.txt")
      "SAMLResponse:" <> error_response = File.read!("test/assets/bankid_error_response.txt")
       %{  
          nemid_xml_response: nemid_xml_response,
          bankid_xml_response: bankid_xml_response,
          nemid_base64_response: nemid_base64_response,
          bankid_base64_response: bankid_base64_response, 
          error_response: error_response
      }
    end

    test "Check BankID signature", state do
      assert {:ok, _} = SAML.verify(state.bankid_base64_response)
    end

    test "Check NemID signature", state do
      assert {:ok, _} = SAML.verify(state.nemid_base64_response)
    end

    test "Check condition dates succeeds", state do
      {:ok, xml} = SAML.verify(state.bankid_base64_response)

      fake_server_time = %DateTime{
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

      assert {:ok, _} = xml
        |> SAML.extract_condition_dates()
        |> SAML.compare_condition_dates(fake_server_time)
    end

    test "Check condition dates fails", state do
      {:ok, xml} = SAML.verify(state.bankid_base64_response)
      assert {:error, _} = xml
        |> SAML.extract_condition_dates()
        |> SAML.compare_condition_dates()
    end

    test "Check parsing of NemID SAML response", state do
      assert {:ok, xml} = SAML.verify(state.nemid_base64_response)

      fake_server_time = %DateTime{
        calendar: Calendar.ISO,
        day: 22,
        hour: 10,
        microsecond: { 705000, 3 },
        minute: 0,
        month: 5,
        second: 24,
        std_offset: 0,
        time_zone: "Etc/UTC",
        utc_offset: 0, year: 2018, zone_abbr: "UTC"
      }

      assert {:ok, _} = xml
        |> SAML.extract_condition_dates()
        |> SAML.compare_condition_dates(fake_server_time)
    end
end
