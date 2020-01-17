# frozen_string_literal: true

require_relative 'spec_helper'

RSpec.describe OCSPResponseFetch::CLI do
  let(:subject) do
    __dir__ + '/fixtures/rsa_rsassaPss.crt'
  end

  let(:issuer) do
    __dir__ + '/fixtures/rsa_ca.crt'
  end

  context 'read_certs' do
    it 'should return subject_cert and issuer_cert' do
      expect(OCSPResponseFetch::CLI.send(:read_certs, subject, issuer))
        .to eq [
          OpenSSL::X509::Certificate.new(File.read(subject)),
          OpenSSL::X509::Certificate.new(File.read(issuer))
        ]
    end
  end

  context 'read_certs (no issuer)' do
    it 'should return subject_cert and issuer_cert' do
      allow(OCSPResponseFetch::CLI).to receive(:send_http_get).and_return(
        OpenSSL::X509::Certificate.new(File.read(issuer)).to_der
      )

      expect(OCSPResponseFetch::CLI.send(:read_certs, subject))
        .to eq [
          OpenSSL::X509::Certificate.new(File.read(subject)),
          OpenSSL::X509::Certificate.new(File.read(issuer))
        ]
    end
  end
end
