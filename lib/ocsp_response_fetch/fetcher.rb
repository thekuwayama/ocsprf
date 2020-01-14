# frozen_string_literal: true

using OCSPResponseFetch::Refinements

module OCSPResponseFetch
  class Fetcher
    # @param ee_cert [OpenSSL::X509::Certificate]
    # @param inter_cert [OpenSSL::X509::Certificate]
    #
    # @raise [RuntimeError]
    def initialize(ee_cert, inter_cert)
      @certs_chain = [ee_cert, inter_cert]
      @cid = OpenSSL::OCSP::CertificateId.new(ee_cert, inter_cert)
      @ocsp_uri = ee_cert.ocsp_uris
                        &.find { |u| URI::DEFAULT_PARSER.make_regexp =~ u }
      raise 'OpenSSL::X509::Certificate#ocsp_uris failed' if @ocsp_uri.nil?
    end

    def run
      request_and_validate(
        @cid,
        @ocsp_uri,
        @certs_chain
      )
    end

    private

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
      rescue Timeout::Error => e
        raise OCSPResponseFetch::Error::Error, e.inspect
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
