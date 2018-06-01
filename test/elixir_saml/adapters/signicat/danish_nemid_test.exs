defmodule DanishNemIDTest do
  use ExUnit.Case
  alias ElixirSaml.Adapters.Signicat.DanishNemID, as: NemID
  doctest NemID

  setup_all do
    "SAMLResponse:" <> response = File.read!("./test/assets/nemid_response.txt")
    "SAMLResponse:" <> error_response = File.read!("./test/assets/nemid_error_response.txt")
    %{response: response, error_response: error_response}
  end

  test "Successful NemID authorization with signicat.com", state do
    assert {:ok, %NemID.UserData{}} = NemID.verify(state.response)
  end

  test "User cancelled NemID authorization with signicat.com", state do
    assert {:error,
      %NemID.InvalidResponse{message: "User cancelled authentication"}
    } = NemID.verify(state.error_response)
  end

  test "Determine gender from Danish name ID", state do
    assert {:ok, %NemID.UserData{gender: "male"}} = NemID.verify(state.response)
  end
end
