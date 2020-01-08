# frozen_string_literal: true

require_relative 'helper'

def fetch
  ee, inter = parse_options
  fetcher = OCSPResponseFetcher.new(
    OpenSSL::X509::Certificate.new(File.read(ee)),
    OpenSSL::X509::Certificate.new(File.read(inter))
  )
  fetcher.run
end

fetch