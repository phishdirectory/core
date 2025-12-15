# frozen_string_literal: true

ENV["RAILS_ENV"] ||= "test"
require_relative "../config/environment"
require "rails/test_help"

module ActiveSupport
  class TestCase
    # Run tests in parallel with specified workers
    parallelize(workers: :number_of_processors)

    # Setup all fixtures in test/fixtures/*.yml
    # fixtures :all

    # Add helper methods for authentication in tests
    def sign_in_as(user)
      session = User::Session.create_for_user(
        user,
        ip: "127.0.0.1",
        device_info: "Test Browser",
        user_agent: "Rails Test"
      )
      @session_token = session.session_token
      session
    end

    def api_headers(api_key: nil)
      headers = { "Content-Type" => "application/json", "Accept" => "application/json" }
      headers["Authorization"] = "Bearer #{api_key}" if api_key
      headers
    end

    def create_test_user(attrs = {})
      User.create!(
        {
          email: "test#{SecureRandom.hex(4)}@example.com",
          username: "testuser#{SecureRandom.hex(4)}",
          first_name: "Test",
          last_name: "User",
          status: :active,
          access_level: :user
        }.merge(attrs)
      )
    end

    def create_test_service(attrs = {})
      Service.create!(
        {
          name: "test-service-#{SecureRandom.hex(4)}",
          status: :active
        }.merge(attrs)
      )
    end
  end
end

module ActionDispatch
  class IntegrationTest
    def sign_in(user)
      session = sign_in_as(user)
      # Set session cookie for integration tests
      post login_path, params: { email: user.email }
      user.send_magic_link
      get magic_link_login_path(token: user.magic_link_token)
      session
    end
  end
end
