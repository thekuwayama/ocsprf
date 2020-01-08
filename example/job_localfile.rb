# frozen_string_literal: true

require_relative 'helper'

ee, inter = parse_options
ee_cert = OpenSSL::X509::Certificate.new(File.read(ee))
inter_cert = OpenSSL::X509::Certificate.new(File.read(inter))
key = ee_cert.subject.to_s + ' ' \
      + ee_cert.serial.to_s(16).scan(/.{1,2}/).join(':')
logger = Logger.new(STDERR)
logger.progname = "OCSPResponse Fetcher #{key}"

CACHE_FILE_PATH = '/tmp/ocsp_response.der'

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

fetcher = OCSPResponseFetcher.new(
  ee_cert,
  inter_cert,
  read_cache: read_local_file,
  write_cache: write_local_file,
  logger: logger
)
fetcher.run
