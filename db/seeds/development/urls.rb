# frozen_string_literal: true

# Development seed data for Phish::Url
# Creates test URLs with various verdicts for testing classification flow
#
# Run with: bin/rails db:seed

module Seeds
  module DEVELOPMENT
    class Urls
      # Phishing URLs - specific malicious pages
      PHISHING_URLS = [
        { url: "https://paypa1-secure.com/login/verify", confidence: 0.96 },
        { url: "https://signin.amaz0n-support.net/ap/signin", confidence: 0.91 },
        { url: "https://account-verify.netflix-billing.com/update", confidence: 0.88 },
        { url: "https://secure-login.bankofamer1ca.com/auth", confidence: 0.94 },
        { url: "https://steamcommunity-trade.ru/tradeoffer/new", confidence: 0.89 },
        { url: "https://discord-nitro-gift.click/claim/free", confidence: 0.92 },
        { url: "https://appleid-verify.support/account/locked", confidence: 0.90 },
        { url: "https://crypto-airdrop.xyz/claim/ethereum", confidence: 0.87 },
      ].freeze

      # Suspicious URLs - may be phishing
      SUSPICIOUS_URLS = [
        { url: "https://free-robux-generator.click/get", confidence: 0.62 },
        { url: "https://amazon-deals-today.biz/offer/iphone", confidence: 0.58 },
        { url: "https://work-from-home-jobs.info/apply", confidence: 0.55 },
        { url: "https://lottery-winner-claim.net/prize", confidence: 0.60 },
      ].freeze

      # Clean URLs - known safe
      CLEAN_URLS = [
        { url: "https://www.google.com/search?q=test", confidence: 0.99 },
        { url: "https://github.com/anthropics/claude", confidence: 0.99 },
        { url: "https://stackoverflow.com/questions", confidence: 0.98 },
      ].freeze

      def self.seed!
        puts "Seeding development URLs..."

        seed_urls(PHISHING_URLS, "phishing")
        seed_urls(SUSPICIOUS_URLS, "suspicious")
        seed_urls(CLEAN_URLS, "clean")

        puts "  Created #{Phish::Url.count} total URLs"
        puts "  - #{Phish::Url.phishing.count} phishing"
        puts "  - #{Phish::Url.suspicious.count} suspicious"
        puts "  - #{Phish::Url.clean.count} clean"
        puts "  - #{Phish::Url.needs_classification.count} needing classification"
      end

      def self.seed_urls(urls, classification)
        urls.each do |data|
          phish_url = Phish::Url.find_or_initialize_by(url: data[:url])

          if phish_url.new_record?
            verdict = Verdict.create!(
              classification: classification,
              confidence_score: data[:confidence]
            )
            phish_url.verdict = verdict
            phish_url.last_checked_at = Time.current
            phish_url.save!
            puts "  + #{phish_url.url.truncate(50)} (#{classification})"
          else
            puts "  = #{phish_url.url.truncate(50)} (already exists)"
          end
        end
      end
    end
  end
end
