module Phish
  class BaseService
    include Faraday

    def initialize
      @conn = Faraday.new(
        url: self.class::BASE_URL,
        headers: all_headers
      )
    end

    protected

    def all_headers
      base_headers.merge(service_headers)
    end

    def base_headers
      {
        "Referer" => "https://phish.directory",
        "User-Agent" => "internal-server@phish.directory",
        "X-Identity" => "internal-server@phish.directory",
      }
    end

    def service_headers
      {}
    end
  end
end
