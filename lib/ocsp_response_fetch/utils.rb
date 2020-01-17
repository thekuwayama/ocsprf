# frozen_string_literal: true

module OCSPResponseFetch
  module Refinements
    refine OpenSSL::X509::Certificate do
      unless method_defined?(:ocsp_uris)
        define_method(:ocsp_uris) do
          aia = extensions.find { |ex| ex.oid == 'authorityInfoAccess' }
          return nil if aia.nil?

          ostr = OpenSSL::ASN1.decode(aia.to_der).value.last
          ocsp = OpenSSL::ASN1.decode(ostr.value)
                              .map(&:value)
                              .select { |des| des.first.value == 'OCSP' }
          ocsp&.map { |o| o[1].value }
        end
      end
    end

    refine OpenSSL::X509::Certificate do
      unless method_defined?(:ca_issuer_uris)
        define_method(:ca_issuer_uris) do
          aia = extensions.find { |ex| ex.oid == 'authorityInfoAccess' }
          return nil if aia.nil?

          ostr = OpenSSL::ASN1.decode(aia.to_der).value.last
          ocsp = OpenSSL::ASN1.decode(ostr.value)
                              .map(&:value)
                              .select { |des| des.first.value == 'caIssuers' }
          ocsp&.map { |o| o[1].value }
        end
      end
    end

    refine OpenSSL::OCSP::Response do
      def to_text
        cert_status = %w[good revoked unknown]

        basic.responses.map do |res|
          <<~"OCSP_RESPONSE"
            OCSP Response Data:
                OCSP Response Status: (#{format('0x%<status>x', status: status)})
                Responses:
                Certificate ID:
                  Hash Algorithm: #{res.certid.hash_algorithm}
                  Issuer Name Hash: #{res.certid.issuer_name_hash.upcase}
                  Issuer Key Hash: #{res.certid.issuer_key_hash.upcase}
                  Serial Number: #{res.certid.serial.to_s(16)}
                Cert Status: #{cert_status[res.cert_status]}
                This Update: #{res.this_update}
                Next Update: #{res.next_update}
          OCSP_RESPONSE
        end.join
      end
    end
  end
end
