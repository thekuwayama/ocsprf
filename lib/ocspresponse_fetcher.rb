# frozen_string_literal: true

require 'openssl'
require 'timeout'
require 'net/http'
require 'logger'

class OCSPResponseFetcher
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
  end
end

using OCSPResponseFetcher::Refinements

class OCSPResponseFetcher
  class << self
    def write_stdout(ocsp_response)
      puts ocsp_response.to_der
                        .unpack1('H*')
                        .scan(/.{1,2}/)
                        .map { |hex| '\x' + hex }
                        .join
    end
  end

  # @param ee_cert [OpenSSL::X509::Certificate]
  # @param inter_cert [OpenSSL::X509::Certificate]
  # @param read_cache [Proc] Proc that returns OpenSSL::OCSP::Request
  # @param write_cache [Proc] Proc that receives OpenSSL::OCSP::Request
  # @param logger [Logger]
  #
  # @raise [RuntimeError]
  # rubocop: disable Metrics/ParameterLists
  def initialize(ee_cert, inter_cert, read_cache: nil,
                 write_cache: OCSPResponseFetcher.method(:write_stdout),
                 logger: Logger.new(STDERR))
    @cid = OpenSSL::OCSP::CertificateId.new(ee_cert, inter_cert)
    @ocsp_uri = ee_cert.ocsp_uris
                      &.find { |u| URI::DEFAULT_PARSER.make_regexp =~ u }
    raise 'OpenSSL::X509::Certificate#ocsp_uris failed' if @ocsp_uri.nil?

    @read_cache = read_cache
    @write_cache = write_cache
    @logger = logger
  end
  # rubocop: enable Metrics/ParameterLists

  def run
    ocsp_response = @read_cache&.call
    if ocsp_response.nil?
      @logger.warn('cache miss')
      ocsp_response = request_and_validate(@cid, @ocsp_uri)
    end

    begin
      @write_cache&.call(ocsp_response) unless ocsp_response.nil?
    rescue StandardError => e
      @logger.warn(e)
    end
  end

  private

  # @return [OpenSSL::OCSP::Response, nil]
  def request_and_validate(cid, ocsp_uri)
    ocsp_request = gen_ocsp_request(cid)
    ocsp_response = nil
    begin
      Timeout.timeout(2) do
        ocsp_response = send_ocsp_request(ocsp_request, ocsp_uri)
      end
    rescue StandardError => e
      @logger.warn(e)
      return nil
    end

    check_nonce = ocsp_request.check_nonce(ocsp_response.basic)
    unless [-1, 1].include?(check_nonce)
      @logger.warn("OCSPResponse's nonce is invalid")
      return nil
    end

    if ocsp_response.status != OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
      @logger.warn("OCSPResponse's status is NOT success")
      return nil
    end

    status = ocsp_response.basic.status.find { |s| s.first.cmp(@cid) }
    if status[1] == OpenSSL::OCSP::V_CERTSTATUS_UNKNOWN
      @logger.warn("OCSPResponse's certificate status code is UNKNOWN")
      return nil
    end

    ocsp_response
  end

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
