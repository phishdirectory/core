module Phish
  class VirusTotalService < BaseService
    BASE_URL = "https://www.virustotal.com"

    def check(to_check)
      # Debug: Check if API key is present
      Rails.logger.debug "API Key present: #{!Rails.application.credentials.dig(:virustotal, :api_key).nil?}"
      Rails.logger.debug "Headers: #{@conn.headers}"

      response = @conn.get("/api/v3/domains/#{to_check}")

      if response.success?
        body = JSON.parse(response.body)
        Rails.logger.debug "Domain info: #{body}"
        body
      else
        Rails.logger.debug "Request failed: #{response.status}"
        Rails.logger.debug "Response body: #{response.body}"
        nil
      end

    end

    def report(to_report)

    end

    protected

    def service_headers
      {
        "x-apikey" => Rails.application.credentials.dig(:virustotal, :api_key)
      }
    end
  end
end
