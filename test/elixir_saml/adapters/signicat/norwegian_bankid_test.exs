defmodule NorwegianBankIDTest do
  use ExUnit.Case
  alias ElixirSAML.{Identity, InvalidResponse}

  test "Successful BankID authorization with signicat.com" do
    {:ok, bankid_response} = File.read("test/assets/bankid")
    assert {:ok, %Identity{ origin: :norwegian_bankid }} = ElixirSAML.verify(bankid_response)
  end

  test "User cancelled BankID authorization with signicat.com" do
    {:ok, error_response} = File.read("test/assets/bankid_error")
    assert {:error, %InvalidResponse{message: "User cancelled authentication"}} =
             ElixirSAML.verify(error_response)
  end

  test "Determine gender from Norwegian national ID" do
    {:ok, bankid_response} = File.read("test/assets/bankid")
    assert {:ok, %Identity{gender: "male"}} = ElixirSAML.verify(bankid_response)
  end
end
