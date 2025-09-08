# frozen_string_literal: true

module Phish
  class WalshyService < BaseService
    BASE_URL = "https://bad-domains.walshy.dev"


    def check(to_check)
      response = @conn.post("/check", { domain: to_check }.to_json)

      if response.success?
        body = JSON.parse(response.body)
        bad_domain = body["badDomain"]
        detection = body["detection"]
        Rails.logger.debug "badDomain: #{bad_domain}, detection: #{detection}"
        body
      else
        Rails.logger.debug "Request failed: #{response.status}"
        nil
      end


    end

    def report(to_report)
      response = @conn.post("/report", { domain: to_report }.to_json)

      if response.success?
        body = JSON.parse(response.body)
        Rails.logger.debug "Reported domain: #{body}"
        body
      else
        Rails.logger.debug "Request failed: #{response.status}"
        nil
      end

    end

    def blk_fetch
      response = @conn.get("/domains.json")

      if response.success?
        body = JSON.parse(response.body)
        Rails.logger.debug "Fetched blacklist: #{body.size} domains"
        body
      else
        Rails.logger.debug "Request failed: #{response.status}"
        nil
      end

    end

  end
end
