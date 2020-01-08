# frozen_string_literal: true

require_relative 'helper'
require 'redis'

ee, inter = parse_options
ee_cert = OpenSSL::X509::Certificate.new(File.read(ee))
inter_cert = OpenSSL::X509::Certificate.new(File.read(inter))
key = ee_cert.subject.to_s + ' ' \
      + ee_cert.serial.to_s(16).scan(/.{1,2}/).join(':')

REDIS_HOST = 'localhost'
REDIS_PORT = 6379

redis = Redis.new(host: REDIS_HOST, port: REDIS_PORT)
read_redis = lambda do
  der = redis.get(key)
  return nil if der.nil?

  ocsp_response = OpenSSL::OCSP::Response.new(der)
  return nil if ocsp_response.basic.status.first[5] < Time.now

  ocsp_response
end

write_redis = lambda do |ocsp_response|
  redis.set(key, ocsp_response.to_der)
end

fetcher = OCSPResponseFetcher.new(
  ee_cert,
  inter_cert,
  nil,
  read_redis,
  write_redis
)
fetcher.run
