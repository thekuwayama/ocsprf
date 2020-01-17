# frozen_string_literal: true

using OCSPResponseFetch::Refinements

module OCSPResponseFetch
  class Fetcher
    # @param subject_cert [OpenSSL::X509::Certificate]
    # @param issuer_cert [OpenSSL::X509::Certificate]
    #
    # @raise [OCSPResponseFetch::Error::Error]
    def initialize(subject_cert, issuer_cert)
      @certs_chain = [subject_cert, issuer_cert]
      @cid = OpenSSL::OCSP::CertificateId.new(subject_cert, issuer_cert)
      @ocsp_uri = subject_cert.ocsp_uris
                    &.find { |u| URI::DEFAULT_PARSER.make_regexp =~ u }
      return unless @ocsp_uri.nil?

      raise OCSPResponseFetch::Error::FetchFailedError,
            'Certificate does not contain OCSP URL'
    end

    def run
      Fetcher.request_and_validate(@cid, @ocsp_uri, @certs_chain)
    end

    class << self
      # @return [OpenSSL::OCSP::Response, nil]
      # rubocop: disable Metrics/CyclomaticComplexity
      # rubocop: disable Metrics/MethodLength
      # rubocop: disable Metrics/PerceivedComplexity
      def request_and_validate(cid, ocsp_uri, certs)
        ocsp_request = gen_ocsp_request(cid)
        ocsp_response = nil
        begin
          Timeout.timeout(2) do
            ocsp_response = send_ocsp_request(ocsp_request, ocsp_uri)
          end
        rescue Timeout::Error
          raise OCSPResponseFetch::Error::FetchFailedError,
                'Timeout to access OCSP Responder'
        end

        if ocsp_response&.status != OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
          raise OCSPResponseFetch::Error::FetchFailedError,
                'OCSPResponseStatus is not successful'
        end

        check_nonce = ocsp_request.check_nonce(ocsp_response.basic)
        unless [-1, 1].include?(check_nonce)
          raise OCSPResponseFetch::Error::FetchFailedError,
                'OCSPResponse nonce is invalid'
        end

        store = OpenSSL::X509::Store.new
        store.set_default_paths
        unless ocsp_response.basic.verify(certs, store)
          raise OCSPResponseFetch::Error::FetchFailedError,
                'OCSPResponse signature is invalid'
        end

        status = ocsp_response.basic.find_response(cid)
        if status.cert_status == OpenSSL::OCSP::V_CERTSTATUS_UNKNOWN
          raise OCSPResponseFetch::Error::FetchFailedError,
                'OCSPResponse CertStatus is unknown'
        elsif status.cert_status == OpenSSL::OCSP::V_CERTSTATUS_REVOKED
          raise OCSPResponseFetch::Error::RevokedError,
                'OCSPResponse CertStatus is revoked'
        end

        ocsp_response
      end
      # rubocop: enable Metrics/CyclomaticComplexity
      # rubocop: enable Metrics/MethodLength
      # rubocop: enable Metrics/PerceivedComplexity

      def gen_ocsp_request(cid)
        ocsp_request = OpenSSL::OCSP::Request.new
        ocsp_request.add_certid(cid)
        ocsp_request.add_nonce
        ocsp_request
      end

      def send_ocsp_request(ocsp_request, uri_string)
        uri = URI.parse(uri_string)
        path = uri.path
        path = '/' if path.nil? || path.empty?
        http_response = Net::HTTP.start(uri.host, uri.port) do |http|
          http.post(
            path,
            ocsp_request.to_der,
            'content-type' => 'application/ocsp-request'
          )
        end

        OpenSSL::OCSP::Response.new(http_response.body)
      end
    end
  end
end
