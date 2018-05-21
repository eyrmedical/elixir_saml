defmodule NemIdTest do
    use ExUnit.Case
    doctest NemId

    test "nemid authorization with signicat.com" do
        response = parse_bin(File.read!("./test/nemid_response.txt"))
        {:ok, data} = NemId.verify(response)
        assert data
    end

    defp parse_bin("SAMLResponse:" <> response) do
        %{"SAMLResponse" => response}
    end
end
