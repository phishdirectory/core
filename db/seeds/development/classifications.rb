# frozen_string_literal: true

# Development seed data for Scam::Classification
# Creates example classification votes to show how consensus works
#
# Run with: bin/rails db:seed

module Seeds
  module DEVELOPMENT
    class Classifications
      # Pre-classify some domains with votes from different users
      CLASSIFIED_DOMAINS = [
        {
          domain: "fake-paypal-login.com",
          votes: [
            { user_email: "trusted@example.com", category: "credential_theft", subcategory: "phishing_email" },
            { user_email: "trusted2@example.com", category: "credential_theft", subcategory: "fake_login_page" }
          ]
        },
        {
          domain: "crypto-giveaway-eth.io",
          votes: [
            { user_email: "trusted@example.com", category: "financial_crypto", subcategory: "cryptocurrency_investment" },
            { user_email: "admin@example.com", category: "financial_crypto", subcategory: "rug_pull" }
          ]
        },
        {
          domain: "steam-trade-offer.ru",
          votes: [
            { user_email: "trusted@example.com", category: "gaming", subcategory: "steam_trade" }
          ]
        },
        {
          domain: "discord-nitro-free.gift",
          votes: [
            { user_email: "trusted2@example.com", category: "gaming", subcategory: "account_theft" }
          ]
        },
        {
          domain: "job-offer-remote.biz",
          votes: [
            { user_email: "trusted@example.com", category: "job_employment", subcategory: "fake_job_offer" }
          ]
        }
      ].freeze

      def self.seed!
        puts "Seeding development classifications..."

        votes_created = 0

        CLASSIFIED_DOMAINS.each do |data|
          domain = Phish::Domain.find_by(domain: data[:domain])

          unless domain
            puts "  ! Domain #{data[:domain]} not found, skipping..."
            next
          end

          data[:votes].each do |vote|
            user = User.find_by(email: vote[:user_email])

            unless user
              puts "  ! User #{vote[:user_email]} not found, skipping..."
              next
            end

            # Skip if already classified by this user
            if domain.classified_by?(user)
              puts "  = #{data[:domain]}: already classified by #{user.email}"
              next
            end

            # Add classification
            begin
              domain.add_classification!(
                user: user,
                category: vote[:category],
                subcategory: vote[:subcategory]
              )
              puts "  + #{data[:domain]}: #{vote[:category]}/#{vote[:subcategory]} by #{user.first_name}"
              votes_created += 1
            rescue ArgumentError => e
              puts "  ! #{data[:domain]}: #{e.message}"
            end
          end
        end

        puts "  Created #{votes_created} classification votes"
        puts "  Domains with classifications: #{Phish::Domain.categorized.count}"
        puts "  Domains still needing classification: #{Phish::Domain.needs_classification.count}"
      end
    end
  end
end
