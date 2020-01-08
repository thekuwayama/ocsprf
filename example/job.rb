# frozen_string_literal: true

$LOAD_PATH << __dir__ + '/../lib'

require 'optparse'
require 'ocspresponse_fetcher'

def parse_options(argv = ARGV)
  op = OptionParser.new

  op.banner += ' END_ENTITY_CERT ITERMEDIATE_CERT'
  begin
    args = op.parse(argv)
  rescue OptionParser::InvalidOption => e
    puts op.to_s
    puts "error: #{e.message}"
    exit 1
  end

  if args.size != 2
    puts op.to_s
    puts 'error: number of arguments is not 2'
    exit 1
  end

  args
end

def fetch
  ee, interm = parse_options
  fetcher = OCSPResponseFetcher.new(
    OpenSSL::X509::Certificate.new(File.read(ee)),
    OpenSSL::X509::Certificate.new(File.read(interm))
  )
  fetcher.run
end

fetch
# $ bundle exec ruby example/job.rb tmp/ee.pem tmp/interm.pem
