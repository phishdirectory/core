# frozen_string_literal: true

# Development seed data for Phish::Domain
# Creates test domains with various verdicts for testing classification flow
#
# Run with: bin/rails db:seed

module Seeds
  module DEVELOPMENT
    class Domains
      # Phishing domains - high confidence threats
      PHISHING_DOMAINS = [
        { domain: "fake-paypal-login.com", confidence: 0.95 },
        { domain: "amaz0n-security-alert.net", confidence: 0.88 },
        { domain: "crypto-giveaway-eth.io", confidence: 0.92 },
        { domain: "netflix-verify-account.com", confidence: 0.89 },
        { domain: "steam-trade-offer.ru", confidence: 0.91 },
        { domain: "apple-id-locked.support", confidence: 0.94 },
        { domain: "microsoft-365-verify.click", confidence: 0.87 },
        { domain: "bank0famerica-secure.com", confidence: 0.96 },
        { domain: "coinbase-airdrop.xyz", confidence: 0.90 },
        { domain: "discord-nitro-free.gift", confidence: 0.93 }
      ].freeze

      # Suspicious domains - lower confidence, may be legitimate
      SUSPICIOUS_DOMAINS = [
        { domain: "suspicious-bank-offer.org", confidence: 0.65 },
        { domain: "free-iphone-winner.click", confidence: 0.55 },
        { domain: "job-offer-remote.biz", confidence: 0.60 },
        { domain: "crypto-trading-bot.net", confidence: 0.58 },
        { domain: "prize-claim-now.info", confidence: 0.62 }
      ].freeze

      # Clean domains - known safe
      CLEAN_DOMAINS = [
        { domain: "google.com", confidence: 0.99 },
        { domain: "github.com", confidence: 0.99 },
        { domain: "stackoverflow.com", confidence: 0.98 }
      ].freeze

      def self.seed!
        puts "Seeding development domains..."

        seed_domains(PHISHING_DOMAINS, "phishing")
        seed_domains(SUSPICIOUS_DOMAINS, "suspicious")
        seed_domains(CLEAN_DOMAINS, "clean")

        puts "  Created #{Phish::Domain.count} total domains"
        puts "  - #{Phish::Domain.phishing.count} phishing"
        puts "  - #{Phish::Domain.suspicious.count} suspicious"
        puts "  - #{Phish::Domain.clean.count} clean"
        puts "  - #{Phish::Domain.needs_classification.count} needing classification"
      end

      def self.seed_domains(domains, classification)
        domains.each do |data|
          domain = Phish::Domain.find_or_initialize_by(domain: data[:domain])

          if domain.new_record?
            verdict = Verdict.create!(
              classification: classification,
              confidence_score: data[:confidence]
            )
            domain.verdict = verdict
            domain.last_checked_at = Time.current
            domain.save!
            puts "  + #{domain.domain} (#{classification}, #{(data[:confidence] * 100).round}%)"
          else
            puts "  = #{domain.domain} (already exists)"
          end
        end
      end
    end
  end
end
