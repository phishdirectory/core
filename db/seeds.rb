# frozen_string_literal: true

# This file should ensure the existence of records required to run the application in every environment (production,
# development, test). The code here should be idempotent so that it can be executed at any point in every environment.
# The data can then be loaded with the bin/rails db:seed command (or created alongside the database with db:setup).
#
# Example:
#
#   ["Action", "Comedy", "Drama", "Horror"].each do |genre_name|
#     MovieGenre.find_or_create_by!(name: genre_name)
#   end
#

puts "Seeding data..."

User.find_or_create_by!(email: "internal+owner@phish.directory") do |user|
  user.first_name = "Internal"
  user.last_name = "Owner"
  user.access_level = "owner"
  user.status = "active"
  user.email_verified = true
  user.email_verified_at = Time.current
  user.staff = true
  user.pd_dev = true
end

User.find_or_create_by!(email: "jasper.mayone@phish.directory") do |user|
  user.first_name = "Jasper"
  user.last_name = "Mayone"
  user.access_level = "owner"
  user.status = "active"
  user.email_verified = true
  user.email_verified_at = Time.current
  user.staff = true
  user.pd_dev = true
end


User.find_or_create_by!(email: "internal+superadmin@phish.directory") do |user|
  user.first_name = "Internal"
  user.last_name = "Superadmin"
  user.access_level = "superadmin"
  user.status = "active"
  user.email_verified = true
  user.email_verified_at = Time.current
  user.staff = true
  user.pd_dev = true
end

User.find_or_create_by!(email: "internal+admin@phish.directory") do |user|
  user.first_name = "Internal"
  user.last_name = "Admin"
  user.access_level = "admin"
  user.status = "active"
  user.email_verified = true
  user.email_verified_at = Time.current
  user.staff = true
  user.pd_dev = true
end


User.find_or_create_by!(email: "internal+trusted@phish.directory") do |user|
  user.first_name = "Internal"
  user.last_name = "Trusted"
  user.access_level = "trusted"
  user.status = "active"
  user.email_verified = true
  user.email_verified_at = Time.current
  user.staff = false
  user.pd_dev = false
end

User.find_or_create_by!(email: "internal+user@phish.directory") do |user|
  user.first_name = "Internal"
  user.last_name = "User"
  user.access_level = "user"
  user.status = "active"
  user.email_verified = true
  user.email_verified_at = Time.current
  user.staff = false
  user.pd_dev = false
end

puts "Seed data successfully created!"
