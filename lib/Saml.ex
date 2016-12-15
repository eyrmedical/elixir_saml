defmodule Saml do
    @moduledoc """
    Verify consistency of SAML 1.0 requests.
    Then you need just to verify your signature - use verify_signature.
    Full verification is done by esaml Erlang library, but keep in mind that
    we don't verify SAML 1.0 assertions in it.
    """

	import SweetXml

    @doc """
    Verify that assertion was signed by certificate.

        iex> assertion = File.read!("./lib/assertion.txt")
        iex> certificate = File.read!("./lib/certificate.pem")
        iex> Saml.verify_signature(assertion, certificate)
        true
    """
	def verify_signature(assertion, certificate) when is_binary(assertion) do
		Base.decode64!(assertion, ignore: :whitespace, padding: false)
		|> initiate_map(certificate)
		|> validate(assertion)
	end

    @doc """
    Verify that assertion was signed by certificate using Erlang native modules.
    Keep in mind that we don't verify digest for the assertion block.

        iex> assertion = File.read!("./lib/assertion.txt")
        iex> Saml.verify(assertion)
        :ok
    """
    def verify(assertion) do
        xml = Base.decode64!(assertion, ignore: :whitespace, padding: false)
        {doc, []} =
            xml
            |> :binary.bin_to_list
            |> :xmerl_scan.string([quiet: true])

        :xmerl_dsig.verify(doc)
    end

	defp validate(map, _assertion) do
		:public_key.verify(
            map[:data],
            map[:digest_algorithm],
            map[:signature_value],
            map[:public_key]
        )
	end

	defp initiate_map(xml, certificate) do
        signature = xml
        |> xpath(~x"ds:Signature")
        |> :xmerl_c14n.c14n
        |> xpath(~x"ds:SignatureValue/text()")
        |> :erlang.list_to_binary
        |> String.replace("\r", "", global: true)
        |> String.replace("\n", "", global: true)
        |> Base.decode64!

        data = xml
        |> xpath(~x"ds:Signature/ds:SignedInfo")
        |> :xmerl_c14n.c14n
        |> :erlang.list_to_binary

		%{
            :data                   => data,
			:digest_algorithm 		=> xpath(xml, ~x"//*[local-name()='DigestMethod']/@Algorithm") |> check_algorithm,
			:digest_value 			=> xpath(xml, ~x"//*[local-name()='DigestValue']/text()") |> to_string,
			:signature_algorithm 	=> xpath(xml, ~x"//*[local-name()='SignatureMethod']/@Algorithm") |> check_algorithm,
			:signature_value 		=> signature,
			:x509_certificate		=> xpath(xml, ~x"//*[local-name()='X509Certificate']/text()") |> format_x509,
			:assertion				=> xpath(xml, ~x"//*[local-name()='Assertion']/text()") |> IO.inspect,
			:public_key 			=> certificate |> decode_pem
		}
	end

	defp check_algorithm(algorithm) do
		case algorithm do
			'http://www.w3.org/2000/09/xmldsig#sha1' 					-> :sha
			'http://www.w3.org/2001/04/xmlenc#sha256' 					-> :sha256
			'http://www.w3.org/2001/04/xmlenc#sha512' 					-> :sha512
			'http://www.w3.org/2000/09/xmldsig#rsa-sha1' 				-> :sha
			'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'         -> :sha256
			'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512'         -> :sha512
			'http://www.w3.org/2000/09/xmldsig#hmac-sha1'               -> :hmac_sha1
			_                                                           -> :sha
		end
	end

	defp format_x509(cert) do
		"-----BEGIN CERTIFICATE-----\n#{cert}\n-----END CERTIFICATE-----"
		|> decode_pem
	end

	defp decode_pem(binary) when is_binary(binary) do
		[{:Certificate, cert, :not_encrypted}] = :public_key.pem_decode(binary)
        decoded_cert = :public_key.pkix_decode_cert(cert, :otp)
        {:OTPCertificate, 
            {:OTPTBSCertificate, _, _, _, _, _, _,
                {:OTPSubjectPublicKeyInfo, _,
                    {:RSAPublicKey, public_key, size}
                }, _, _, _
            }, _, _
        } = decoded_cert
        {:RSAPublicKey, public_key, size}
	end
end
