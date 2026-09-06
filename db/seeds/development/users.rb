# frozen_string_literal: true

# Development seed data for Users
# Creates test users with different access levels for permission testing
#
# Run with: bin/rails db:seed

module Seeds
  module DEVELOPMENT
    class Users
      TEST_USERS = [
        # Regular users
        { email: "user@example.com", first_name: "Regular", last_name: "User", access_level: :user },
        { email: "user2@example.com", first_name: "Another", last_name: "User", access_level: :user },

        # Trusted users (can classify)
        { email: "trusted@example.com", first_name: "Trusted", last_name: "Classifier", access_level: :trusted },
        { email: "trusted2@example.com", first_name: "Senior", last_name: "Classifier", access_level: :trusted },

        # Admin users
        { email: "admin@example.com", first_name: "Admin", last_name: "User", access_level: :admin, staff: true },

        # Superadmin
        { email: "superadmin@example.com", first_name: "Super", last_name: "Admin", access_level: :superadmin, staff: true }
      ].freeze

      def self.seed!
        puts "Seeding development users..."

        TEST_USERS.each do |data|
          user = User.find_or_initialize_by(email: data[:email])

          if user.new_record?
            user.assign_attributes(
              first_name: data[:first_name],
              last_name: data[:last_name],
              access_level: data[:access_level],
              staff: data[:staff] || false,
              email_verified: true,
              email_verified_at: Time.current
            )
            user.save!
            puts "  + #{user.email} (#{user.access_level})"
          else
            puts "  = #{user.email} (already exists)"
          end
        end

        puts "  Users by access level:"
        User::ACCESS_LEVELS.each do |level|
          count = User.where(access_level: level).count
          puts "    - #{level}: #{count}" if count > 0
        end
      end
    end
  end
end
