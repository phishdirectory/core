# frozen_string_literal: true

# This file should ensure the existence of records required to run the application
# in every environment (production, development, test).
#
# The code here should be idempotent so that it can be executed at any point in
# every environment. The data can then be loaded with the bin/rails db:seed command
# (or created alongside the database with db:setup).

# Load all seed files from db/seeds/
Dir[Rails.root.join("db/seeds/*.rb")].sort.each { |f| require f }

# Run seeds (all envs)
Seeds::Users.seed!
Seeds::AbuseContacts.seed!
Seeds::Protections.seed!

# Run development-specific seeds
if Rails.env.development?
  Dir[Rails.root.join("db/seeds/development/*.rb")].sort.each { |f| require f }

  # Order matters: users first, then data that references them
  Seeds::DEVELOPMENT::Users.seed!
  Seeds::DEVELOPMENT::Domains.seed!
  Seeds::DEVELOPMENT::Urls.seed!
  Seeds::DEVELOPMENT::Services.seed!
  Seeds::DEVELOPMENT::ApiKeys.seed!
  Seeds::DEVELOPMENT::Classifications.seed!  # Must run after domains/urls and users
end