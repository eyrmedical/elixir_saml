defmodule ElixirSAML.Helpers do
  @moduledoc false

  import SweetXml, only: [xpath: 2, sigil_x: 2]
  @doc """
  Extracts Assertion Attributes from SAML document.
  """
  @spec extract_assertion_attribute(xml, attribute_name) :: attribute_value
  def extract_assertion_attribute(xml, attribute_name) do
    xpath(xml, ~x"Assertion/AttributeStatement/Attribute[contains(@AttributeName,'#{attribute_name}')]/AttributeValue/text()")
  end
  @spec extract_assertion_attribute_as_string(xml, attribute_name) :: attribute_string_value
  def extract_assertion_attribute_as_string(xml, attribute_name) do
    extract_assertion_attribute(xml, attribute_name)
    |> to_string()
  end


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