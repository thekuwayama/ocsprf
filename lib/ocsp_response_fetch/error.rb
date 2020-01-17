# frozen_string_literal: true

module OCSPResponseFetch
  module Error
    # Generic error
    class Error < StandardError; end

    class RevokedError < Error; end
    class FetchFailedError < Error; end
  end
end
