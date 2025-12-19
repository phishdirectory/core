# frozen_string_literal: true

# Seed data for Users
# Pre-populates data for users
#
# Run with: bin/rails db:seed

module Seeds
  class Users

    USERS = [
      { email: "system@phish.directory", first_name: "System", last_name: "User", access_level: :owner, pd_dev: true, staff: true },
      { email: "jasper.mayone@phish.directory", first_name: "Jasper", last_name: "Mayone", access_level: :owner, pd_dev: true, staff: true},
    ].freeze

    def self.seed!
      puts "Seeding users..."

      USERS.each do |u|
        User.find_or_create_by!(email: u[:email], first_name: u[:first_name], last_name: u[:last_name], access_level: u[:access_level], staff: u[:staff], pd_dev: u[:pd_dev])
        end
      end

  end
end