defmodule BankIdTest do
    use ExUnit.Case
    doctest BankId

    test "Successful BankID authorization with signicat.com" do
        response = parse_bin(File.read!("./test/bankid_response.txt"))
        {:ok, data} = BankId.verify(response)
        assert data
    end

    test "User cancelled BankID authorization with signicat.com" do
        response =  parse_bin(File.read!("./test/bankid_error_response.txt"))
                    |> BankId.verify
        assert {:error, %BankId.InvalidResponse{message: "User cancelled authentication"}}
    end

    defp parse_bin("SAMLResponse:" <> response) do
        %{"SAMLResponse" => response}
    end
end
