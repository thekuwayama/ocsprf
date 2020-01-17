# frozen_string_literal: true

using OCSPResponseFetch::Refinements

module OCSPResponseFetch
  class CLI
    # rubocop: disable Metrics/AbcSize
    # rubocop: disable Metrics/MethodLength
    def parse_options(argv = ARGV)
      op = OptionParser.new

      # default value
      opts = {
        inter: nil,
        strict: false,
        verbose: false
      }

      op.on(
        '-i PATH',
        '--inter PATH',
        'intermediate certificate path'
      ) do |v|
        opts[:inter] = v
      end

      op.on(
        '-s',
        '--strict',
        "strict mode                   (default #{opts[:strict]})"
      ) do |v|
        opts[:strict] = v
      end

      op.on(
        '-v',
        '--verbose',
        "verbose mode                  (default #{opts[:verbose]})"
      ) do |v|
        opts[:verbose] = v
      end

      op.banner += ' PATH'
      begin
        args = op.parse(argv)
      rescue OptionParser::InvalidOption => e
        warn op.to_s
        warn "error: #{e.message}"
        exit 1
      end

      if args.size != 1
        warn op.to_s
        warn 'error: number of arguments is not 1'
        exit 1
      end

      unless File.exist?(args.first)
        warn "error: file #{args.first} is not found"
        exit 1
      end

      if !opts[:inter].nil? && !File.exist?(opts[:inter])
        warn "error: file #{opts[:inter]} is not found"
        exit 1
      end

      [args[0], opts]
    end
    # rubocop: enable Metrics/AbcSize
    # rubocop: enable Metrics/MethodLength

    def read_certs(ee, inter)
      ee_cert = OpenSSL::X509::Certificate.new(File.read(ee))
      inter_cert = nil
      if inter.nil? || inter.empty?
        ca_issuer = ee_cert.ca_issuer_uris
                          &.find { |u| URI::DEFAULT_PARSER.make_regexp =~ u }
        if ca_issuer.nil?
          raise OCSPResponseFetch::Error::FetchFailedError,
                'Certificate does not contain Issuer URL'
        end

        inter_cert = get_inter_cert(ca_issuer)
      else
        inter_cert = OpenSSL::X509::Certificate.new(File.read(inter))
      end

      [ee_cert, inter_cert]
    end

    def get_inter_cert(uri_string)
      OpenSSL::X509::Certificate.new(
        send_http_get(uri_string)
      )
    end

    def send_http_get(uri_string)
      uri = URI.parse(uri_string)
      path = uri.path
      path = '/' if path.nil? || path.empty?
      http_response = Net::HTTP.start(uri.host, uri.port) do |http|
        http.get(path)
      end

      http_response.body
    end

    def run
      ee, opts = parse_options
      inter = opts[:inter]
      ee_cert, inter_cert = read_certs(ee, inter)

      fetcher = Fetcher.new(ee_cert, inter_cert)
      begin
        ocsp_response = fetcher.run
      rescue OCSPResponseFetch::Error::RevokedError
        warn 'error: end entity certificate is revoked'
        exit 1
      rescue OCSPResponseFetch::Error::Error => e
        warn e
        exit 1 if opts[:strict]
        exit 0
      end

      warn ocsp_response.to_text if opts[:verbose]
      puts ocsp_response.to_der
    end
  end
end
