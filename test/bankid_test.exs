defmodule BankIdTest do
    use ExUnit.Case
    doctest BankId

    test "bankid authorization with signicat.com" do
        response = parse_bin(File.read!("./test/bankid_response.txt"))
        {:ok, data} = BankId.verify(response)
        assert data
    end

    defp parse_bin("SAMLResponse:" <> response) do
        %{"SAMLResponse" => response}
    end
end
