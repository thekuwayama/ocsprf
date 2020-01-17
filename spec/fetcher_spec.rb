# frozen_string_literal: true

require_relative 'spec_helper'

RSpec.describe OCSPResponseFetch::Fetcher do
  let(:subject_cert) do
    OpenSSL::X509::Certificate.new(
      File.read(__dir__ + '/fixtures/rsa_rsassaPss.crt')
    )
  end

  let(:issuer_cert) do
    OpenSSL::X509::Certificate.new(
      File.read(__dir__ + '/fixtures/rsa_ca.crt')
    )
  end

  let(:cid) do
    OpenSSL::OCSP::CertificateId.new(subject_cert, issuer_cert)
  end

  let(:nonce) do
    'nonce'
  end

  let(:ocsp_request) do
    ocsp_request = OpenSSL::OCSP::Request.new
    ocsp_request.add_certid(cid)
    ocsp_request.add_nonce(nonce)
    ocsp_request
  end

  let(:ocsp_response) do
    bres = OpenSSL::OCSP::BasicResponse.new
    bres.add_status(
      cid,
      OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL,
      OpenSSL::OCSP::V_CERTSTATUS_GOOD,
      Time.now + (60 * 60 * 24 * 365 * 10),
      Time.new,
      Time.now + (60 * 60 * 24 * 14),
      []
    )
    bres.add_nonce(nonce)
    bres.sign(
      issuer_cert,
      OpenSSL::PKey.read(
        File.read(__dir__ + '/fixtures/rsa_ca.key')
      )
    )

    OpenSSL::OCSP::Response.create(
      OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL,
      bres
    )
  end

  before do
    ENV[OpenSSL::X509::DEFAULT_CERT_FILE_ENV] = __dir__ + '/fixtures/rsa_ca.crt'
  end

  context 'request_and_validate' do
    it 'should return a valid OCSP Response' do
      allow(OCSPResponseFetch::Fetcher).to receive(:new)
      allow(OCSPResponseFetch::Fetcher).to receive(:gen_ocsp_request)
        .and_return(ocsp_request)
      allow(OCSPResponseFetch::Fetcher).to receive(:send_ocsp_request)
        .and_return(ocsp_response)

      expect(OCSPResponseFetch::Fetcher.request_and_validate(
               cid,
               'http://localhost/ocsp',
               [subject_cert, issuer_cert]
             )).to eq ocsp_response
    end
  end
end
