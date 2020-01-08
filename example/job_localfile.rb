# frozen_string_literal: true

require_relative 'helper'

CACHE_FILE_PATH = '/tmp/ocsp_response.der'

def fetch
  read_local_file = lambda do
    return nil unless File.exist?(CACHE_FILE_PATH)

    der = File.binread(CACHE_FILE_PATH)
    ocsp_response = OpenSSL::OCSP::Response.new(der)
    return nil if ocsp_response.basic.status.first[5] < Time.now

    ocsp_response
  end

  write_local_file = lambda do |ocsp_response|
    File.binwrite(CACHE_FILE_PATH, ocsp_response.to_der)
  end

  ee, inter = parse_options
  fetcher = OCSPResponseFetcher.new(
    OpenSSL::X509::Certificate.new(File.read(ee)),
    OpenSSL::X509::Certificate.new(File.read(inter)),
    nil,
    read_local_file,
    write_local_file
  )
  fetcher.run
end

fetch
