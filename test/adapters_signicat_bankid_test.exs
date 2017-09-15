defmodule NorwegianBankIDTest do
    use ExUnit.Case
    alias NorwegianBankID, as: BankID
    doctest BankID

    setup_all do
        "SAMLResponse:" <> response = File.read!("./test/assets/bankid_response.txt")
        "SAMLResponse:" <> error_response = File.read!("./test/assets/bankid_error_response.txt")
        %{response: response, error_response: error_response }
    end

    test "Successful BankID authorization with signicat.com", state do
        assert {:ok, %BankID.UserData{}} = BankID.verify(state.response)
    end

    test "User cancelled BankID authorization with signicat.com", state do
        assert {:error,
            %BankID.InvalidResponse{message: "User cancelled authentication"}
        } = BankID.verify(state.error_response)
    end

    test "Determine gender from Norwegian national ID", state do
      assert {:ok, %BankID.UserData{ gender: "male" }} = BankID.verify(state.response)
    end
end
