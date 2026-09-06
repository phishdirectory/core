# frozen_string_literal: true

# Development seed data for UserApiKey
# Creates test API keys for quick API testing
#
# Run with: bin/rails db:seed

module Seeds
  module DEVELOPMENT
    class ApiKeys
      # Keys to create for each test user (by email)
      USER_KEYS = {
        "trusted@example.com" => [
          { name: "Development Key" },
          { name: "Testing Key" }
        ],
        "admin@example.com" => [
          { name: "Admin Dev Key" }
        ]
      }.freeze

      def self.seed!
        puts "Seeding development API keys..."

        keys_created = 0

        USER_KEYS.each do |email, keys|
          user = User.find_by(email: email)

          unless user
            puts "  ! User #{email} not found, skipping..."
            next
          end

          keys.each do |key_data|
            # Check if key with this name already exists
            existing = user.user_api_keys.find_by(name: key_data[:name])

            if existing
              puts "  = #{email}: #{key_data[:name]} (already exists)"
            else
              api_key = user.user_api_keys.create!(name: key_data[:name])
              puts "  + #{email}: #{key_data[:name]}"
              puts "    Key: #{api_key.plaintext_key}"
              keys_created += 1
            end
          end
        end

        puts "  Created #{keys_created} new API keys"
        puts "  Total user API keys: #{UserApiKey.count}"
      end
    end
  end
end
