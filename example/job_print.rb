# frozen_string_literal: true

require_relative 'helper'

ee, inter = parse_options
ee_cert = OpenSSL::X509::Certificate.new(File.read(ee))
inter_cert = OpenSSL::X509::Certificate.new(File.read(inter))
key = ee_cert.subject.to_s + ' ' \
      + ee_cert.serial.to_s(16).scan(/.{1,2}/).join(':')
logger = Logger.new(STDERR)
logger.progname = "OCSPResponse Fetcher #{key}"

fetcher = OCSPResponseFetch.new(
  ee_cert,
  inter_cert,
  logger: logger
)
fetcher.run
