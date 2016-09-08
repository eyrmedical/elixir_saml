defmodule Saml do
	import SweetXml
	def verify(assertion, certificate) when is_binary(assertion) do
		Base.decode64!(assertion, ignore: :whitespace)
		|> initiate_map(certificate)
		|> validate
	end

	defp validate(map) do
		:public_key.verify(map[:assertion], map[:digest_algorithm], map[:digest_value], map[:public_key])
		#map[:digest_algorithm]
		#|> :crypto.hash_init(map[:digest_value])
		# message 							= " "
		# signature_value 			= map[:signature_value]				
		# signature_algorithm		= map[:signature_algorithm]		
		# digest_value					= map[:digest_value]					
		# digest_algorithm			= map[:digest_algorithm]			
		# public_key						= map[:public_key]						
		# x509_certificate			= map[:x509_certificate]			
	end

	defp initiate_map(xml, certificate) do
		%{
			:digest_algorithm 		=> xpath(xml, ~x"//*[local-name()='DigestMethod']/@Algorithm") 		|> check_algorithm,
			:digest_value 				=> xpath(xml, ~x"//*[local-name()='DigestValue']/text()") 				|> to_string,
			:signature_algorithm 	=> xpath(xml, ~x"//*[local-name()='SignatureMethod']/@Algorithm") |> check_algorithm,
			:signature_value 			=> xpath(xml, ~x"//*[local-name()='SignatureValue']/text()") 			|> to_string,
			:x509_certificate			=> xpath(xml, ~x"//*[local-name()='X509Certificate']/text()") 		|> format_x509,
			:assertion						=> xpath(xml, ~x"//*[local-name()='Assertion']/text()") 					|> IO.inspect,
			:public_key 					=> certificate |> decode_pem
		}
	end

	defp check_algorithm(algorithm) do
		case algorithm do
			'http://www.w3.org/2000/09/xmldsig#sha1' 						-> :sha
			'http://www.w3.org/2001/04/xmlenc#sha256' 					-> :sha256
			'http://www.w3.org/2001/04/xmlenc#sha512' 					-> :sha512
			'http://www.w3.org/2000/09/xmldsig#rsa-sha1' 				-> :sha
			'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' -> :rsa_sha256
			'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512' -> :rsa_sha512
			'http://www.w3.org/2000/09/xmldsig#hmac-sha1' 			-> :hmac_sha1
			_ -> :sha
		end
	end

	defp format_x509(cert) do
		"-----BEGIN CERTIFICATE-----\n#{cert}\n-----END CERTIFICATE-----"
		|> to_string
		|> decode_pem
	end

	defp decode_pem(binary) when is_binary(binary) do
		[ pem_entry ] = :public_key.pem_decode(binary)
		:public_key.pem_entry_decode(pem_entry)
	end
end


assertion = File.read!('./lib/assertion.txt')
certificate = File.read!('./lib/certificate.pem')

Saml.verify(assertion, certificate)
|> IO.inspect