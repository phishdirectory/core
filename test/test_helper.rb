# frozen_string_literal: true

# Must be loaded before the application so nothing escapes instrumentation.
# Coverage is opt-in: the suite is fast and this keeps the default run clean.
if ENV["COVERAGE"]
  require "simplecov"
  SimpleCov.start "rails" do
    enable_coverage :branch
    add_filter "/test/"
    add_filter "/config/"

    add_group "Services", "app/services"
    add_group "Jobs", "app/jobs"

    # A ratchet, not a target. Set just below where the suite actually sits
    # (32.8% line, 14.9% branch as of writing) so it catches regressions
    # without blocking work. Raise it as coverage grows.
    #
    # The number is low because the service layer, the report pipeline and
    # most controllers had no tests at all before this series of changes.
    minimum_coverage line: 30, branch: 13
  end
end

ENV["RAILS_ENV"] ||= "test"
require_relative "../config/environment"
require "rails/test_help"
require "webmock/minitest"
require "minitest/mock"

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
        device_info: "Test Browser"
      )
      @session_token = session.session_token
      session
    end

    def api_headers(api_key: nil, user_agent: "TestClient/1.0.0")
      headers = {
        "Content-Type" => "application/json",
        "Accept" => "application/json",
        "User-Agent" => user_agent
      }
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

    def create_test_abuse_contact(attrs = {})
      Report::AbuseContact.create!(
        {
          name: "Test Host #{SecureRandom.hex(4)}",
          contact_type: :hosting,
          method: :email,
          email: "abuse@example.com"
        }.merge(attrs)
      )
    end

    def create_test_report_case(confidence: 0.95, domain_info: {}, sources: [ { "service" => "TestSource" } ])
      domain = Phish::Domain.create!(domain: "bad-#{SecureRandom.hex(4)}.com")
      verdict = Verdict.create!(
        classification: "phishing",
        confidence_score: confidence,
        sources: sources
      )

      Report::Case.create!(
        reportable: domain,
        verdict_snapshot: verdict,
        confidence_at_creation: confidence,
        domain_info: domain_info
      )
    end

    def create_test_submission(report_case, contact)
      report_case.submissions.create!(
        abuse_contact: contact,
        payload: report_case.submissions.build(abuse_contact: contact).build_payload
      )
    end
  end
end

module ActionDispatch
  class IntegrationTest
    # Signs in through the real magic link flow, which is the only way a
    # session cookie actually gets set.
    def sign_in(user)
      token = user.generate_magic_link_token
      get magic_link_login_path(token: token)
      follow_redirect! if response.redirect?
      user
    end
  end
end
