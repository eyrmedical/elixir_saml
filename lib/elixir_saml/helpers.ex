defmodule ElixirSAML.Helpers do
  @moduledoc false

  import SweetXml, only: [xpath: 2, sigil_x: 2]



  @doc """
  Extract SAML value from XML path.
  """
  @spec extract_value(xml, path) :: any()
  def extract_value(xml, path) do
    xpath(xml, string_to_path(path))
  end

    @doc """
  Extract SAML value from XML path.
  """
  @spec extract_value(xml, path) :: any()
  def extract_string_value(xml, path) do
    extract_value(xml, path) |> to_string()
  end

  @spec string_to_path(String.t()) :: path
  defp string_to_path(string) do 
    ~x"#{string}"
  end

end 