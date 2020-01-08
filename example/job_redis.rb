# frozen_string_literal: true

require_relative 'helper'
require 'redis'

ee, inter = parse_options
ee_cert = OpenSSL::X509::Certificate.new(File.read(ee))
inter_cert = OpenSSL::X509::Certificate.new(File.read(inter))
key = ee_cert.subject.to_s + ' ' \
      + ee_cert.serial.to_s(16).scan(/.{1,2}/).join(':')
logger = Logger.new(STDERR)
logger.progname = "OCSPResponse Fetcher #{key}"

REDIS_HOST = 'localhost'
REDIS_PORT = 6379
redis = Redis.new(host: REDIS_HOST, port: REDIS_PORT)

read_redis = lambda do
  begin
    der = redis.get(key)
  rescue StandardError
    logger.warn('Redis#get access failed')
    return nil
  end
  return nil if der.nil?

  ocsp_response = OpenSSL::OCSP::Response.new(der)
  return nil if ocsp_response.basic.status.first[5] < Time.now

  ocsp_response
end

write_redis = lambda do |ocsp_response|
  redis.set(key, ocsp_response.to_der)
rescue StandardError
  logger.warn('Redis#set access failed')
  return nil
end

fetcher = OCSPResponseFetcher.new(
  ee_cert,
  inter_cert,
  read_cache: read_redis,
  write_cache: write_redis,
  logger: logger
)
fetcher.run
