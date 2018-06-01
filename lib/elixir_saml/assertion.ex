defmodule ElixirSAML.Assertion do
	@moduledoc """
	Helper functions for working on a SAML assertion
	"""

	import SweetXml, only: [xpath: 2, sigil_x: 2]
	
	def to_map(xml) do
		
	end

	@doc """
	Extracts Assertion Attributes from SAML document.
	"""
	@spec extract_assertion_attribute(xml, attribute_name) :: attribute_value
	def extract_attribute(xml, attribute_name) do
	  xpath(xml, ~x"Assertion/AttributeStatement/Attribute[contains(@AttributeName,'#{attribute_name}')]/AttributeValue/text()")
	end
	@spec extract_attribute_as_string(xml, attribute_name) :: attribute_string_value
	def extract_attribute(xml, attribute_name) do
	  extract_assertion_attribute(xml, attribute_name)
	  |> to_string()
	end
end
