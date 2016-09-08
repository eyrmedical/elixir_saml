# defmodule SignedXml do
# 	import SweetXml
# 	import ExCrypto

# 	def validate(assertion, certificate) do
# 		map = Base.decode64!(assertion, ignore: :whitespace)
# 					|> initiate_map(certificate)
		
# 		ExPublicKey.verify( map[:digest_value], map[:signature_value], map[:public_key])
# 		|> IO.inspect
# 	end

# 	defp initiate_map(xml, certificate) do
# 		%{
# 			:digest_algorithm 		=> xpath(xml, ~x"//*[local-name()='DigestMethod']/@Algorithm") |> check_algorithm,
# 			:digest_value 				=> xpath(xml, ~x"//*[local-name()='DigestValue']/text()") |> to_string,
# 			:signature_algorithm 	=> xpath(xml, ~x"//*[local-name()='SignatureMethod']/@Algorithm") |> check_algorithm,
# 			:signature_value 			=> xpath(xml, ~x"//*[local-name()='SignatureValue']/text()") |> to_string,
# 			:x509_certificate			=> xpath(xml, ~x"//*[local-name()='X509Certificate']/text()") |> format_x509,
# 			:public_key 					=> certificate #|> :public_key.pem_decode
# 		}
# 	end

# 	defp format_x509(cert) do
# 		'-----BEGIN CERTIFICATE-----\n#{cert}\n-----END CERTIFICATE-----'
# 		|> to_string
# 		#|> :public_key.pem_decode
# 	end

# 	defp check_algorithm(xml) do
# 		case (xml) do
# 			'http://www.w3.org/2000/09/xmldsig#sha1' 						-> 'sha'
# 			'http://www.w3.org/2001/04/xmlenc#sha256' 					-> 'sha256'
# 			'http://www.w3.org/2001/04/xmlenc#sha512' 					-> 'sha512'
# 			'http://www.w3.org/2000/09/xmldsig#rsa-sha1' 				-> :rsa_sha1
# 			'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' -> :rsa_sha256
# 			'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512' -> :rsa_sha512
# 			'http://www.w3.org/2000/09/xmldsig#hmac-sha1' 			-> :hmac_sha1
# 			_ -> :sha1
# 		end
# 	end

# 	defp verify_signature(document) do
# 		:public_key.verify(document[:digest_value], 'sha', document[:signature_value], document[:internal_certificate])
# 	end

# 	defp load_key(certificate_path) do
# 		File.read!(certificate_path)
# 		|> :public_key.pem_decode
# 		|> validate_pem_length
# 		|> load_pem_entry
# 	end

# 	defp validate_pem_length(pem_entries) do
#     case length(pem_entries) do
#       0 -> {:error, "invalid argument"}
#       x when x > 1 -> {:error, "found multiple PEM entries, expected only 1"}
#       x when x == 1 -> {:ok, Enum.at(pem_entries, 0)}
#     end
#   end

#   defp load_pem_entry(pem_entry) do
# 		{:ok, :public_key.pem_entry_decode(pem_entry)}
#   catch
#     kind, error ->
#       ExPublicKey.normalize_error(kind, error)
#   end

# end

# assertion 	= File.read!('./lib/assertion.txt')
# certificate = File.read!('./lib/certificate.pem')

# SignedXml.validate(assertion, certificate)