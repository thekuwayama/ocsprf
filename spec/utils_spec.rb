# frozen_string_literal: true

require_relative 'spec_helper'
using OCSPResponseFetch::Refinements

RSpec.describe OCSPResponseFetch::Refinements do
  context 'OpenSSL::X509::Certificate#ocsp_uris' do
    let(:cert) do
      OpenSSL::X509::Certificate.new(
        File.read(__dir__ + '/fixtures/rsa_rsassaPss.crt')
      )
    end

    it 'should return URL' do
      expect(cert.ocsp_uris).to eq ['http://localhost/ocsp']
    end
  end

  context 'OpenSSL::X509::Certificate#ca_issuer_uris' do
    let(:cert) do
      OpenSSL::X509::Certificate.new(
        File.read(__dir__ + '/fixtures/rsa_rsassaPss.crt')
      )
    end

    it 'should return URL' do
      expect(cert.ca_issuer_uris).to eq ['http://localhost/caIssuers']
    end
  end

  context 'OpenSSL::OCSP::Response#to_text' do
    let(:subject_cert) do
      OpenSSL::X509::Certificate.new(
        File.read(__dir__ + '/fixtures/rsa_rsassaPss.crt')
      )
    end

    let(:issuer_cert) do
      OpenSSL::X509::Certificate.new(
        File.read(__dir__ + '/fixtures/rsa_rsassaPss.crt')
      )
    end

    let(:cid) do
      OpenSSL::OCSP::CertificateId.new(subject_cert, issuer_cert)
    end

    let(:thisupd) do
      Time.now
    end

    let(:nextupd) do
      Time.now + (60 * 60 * 24 * 14)
    end

    let(:ocsp_response) do
      bres = OpenSSL::OCSP::BasicResponse.new
      bres.add_status(
        cid,
        OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL,
        OpenSSL::OCSP::V_CERTSTATUS_GOOD,
        Time.now + (60 * 60 * 24 * 365 * 10),
        thisupd,
        nextupd,
        []
      )
      bres.add_nonce
      bres.sign(
        subject_cert,
        OpenSSL::PKey.read(
          File.read(__dir__ + '/fixtures/rsa_rsassaPss.key')
        )
      )

      OpenSSL::OCSP::Response.create(
        OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL,
        bres
      )
    end

    it 'should return text' do
      expect(ocsp_response.to_text).to eq <<~"OCSP_RESPONSE"
        OCSP Response Data:
            OCSP Response Status: (0x0)
            Responses:
            Certificate ID:
              Hash Algorithm: sha1
              Issuer Name Hash: #{cid.issuer_name_hash.upcase}
              Issuer Key Hash: #{cid.issuer_key_hash.upcase}
              Serial Number: #{cid.serial.to_s(16)}
            Cert Status: good
            This Update: #{thisupd.utc}
            Next Update: #{nextupd.utc}
      OCSP_RESPONSE
    end
  end
end
