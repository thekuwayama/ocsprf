# frozen_string_literal: true

using OCSPResponseFetch::Refinements

module OCSPResponseFetch
  # rubocop: disable Metrics/ClassLength
  class CLI
    class << self
      def run
        subject, opts = parse_options
        issuer = opts[:issuer]
        subject_cert, issuer_cert = read_certs(subject, issuer)

        fetcher = Fetcher.new(subject_cert, issuer_cert)
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

      private

      # rubocop: disable Metrics/AbcSize
      # rubocop: disable Metrics/MethodLength
      def parse_options(argv = ARGV)
        op = OptionParser.new

        # default value
        opts = {
          issuer: nil,
          strict: false,
          verbose: false
        }

        op.on(
          '-i PATH',
          '--issuer PATH',
          'issuer certificate path'
        ) do |v|
          opts[:issuer] = v
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

        if !opts[:issuer].nil? && !File.exist?(opts[:issuer])
          warn "error: file #{opts[:issuer]} is not found"
          exit 1
        end

        [args[0], opts]
      end
      # rubocop: enable Metrics/AbcSize
      # rubocop: enable Metrics/MethodLength

      def read_certs(subject, issuer = nil)
        subject_cert = OpenSSL::X509::Certificate.new(File.read(subject))
        issuer_cert = nil
        if issuer.nil? || issuer.empty?
          ca_issuer = subject_cert.ca_issuer_uris
                        &.find { |u| URI::DEFAULT_PARSER.make_regexp =~ u }
          if ca_issuer.nil?
            raise OCSPResponseFetch::Error::FetchFailedError,
                  'The subject Certificate does not contain Issuer URL'
          end

          begin
            issuer_cert = get_issuer_cert(ca_issuer)
          rescue OpenSSL::X509::CertificateError, Net::OpenTimeout
            raise OCSPResponseFetch::Error::FetchFailedEreror,
                  'Failed to get the issuser Certificate'
          end
        else
          begin
            issuer_cert = OpenSSL::X509::Certificate.new(File.read(issuer))
          rescue OpenSSL::X509::CertificateError
            raise OCSPResponseFetch::Error::FetchFailedEreror,
                  'Failed to get the issuser Certificate'
          end
        end

        [subject_cert, issuer_cert]
      end

      def get_issuer_cert(uri_string)
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
    end
  end
  # rubocop: enable Metrics/ClassLength
end
