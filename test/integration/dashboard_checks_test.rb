# frozen_string_literal: true

require "test_helper"

# The domain, email and phone check pages were three copies of the same view
# that had already drifted. They are now one page driven by a check type, and
# the long-advertised URL check finally exists.
class DashboardChecksTest < ActionDispatch::IntegrationTest
  setup do
    @user = create_test_user
    sign_in(@user)
  end

  # The check calls external threat intelligence services synchronously. Tests
  # that are about the page, not the lookup, stub them out.
  def with_lookups_stubbed(&block)
    noop = ->(record) { record }
    VerdictService.stub(:check_domain!, noop) do
      VerdictService.stub(:check_url!, noop) do
        VerdictService.stub(:check_email!, noop) do
          VerdictService.stub(:check_phone!, noop, &block)
        end
      end
    end
  end

  # ===========================================
  # Every type has a page
  # ===========================================

  test "each check page renders its own form" do
    {
      dashboard_domain_check_path => "Check Domain",
      dashboard_url_check_path => "Check URL",
      dashboard_email_check_path => "Check Email",
      dashboard_phone_check_path => "Check Phone Number"
    }.each do |path, heading|
      get path
      assert_response :success
      assert_select "h1", text: heading
    end
  end

  test "the url check exists at all" do
    get dashboard_url_check_path

    assert_response :success
    assert_select "form[action=?]", dashboard_check_url_path
  end

  test "every check input has a real label, not just a placeholder" do
    [ dashboard_domain_check_path, dashboard_url_check_path,
      dashboard_email_check_path, dashboard_phone_check_path ].each do |path|
      get path
      assert_select "label[for]", { minimum: 1 }, "#{path} has no label for its input"
    end
  end

  # ===========================================
  # Normalization is disclosed
  # ===========================================

  test "checking a pasted link says which domain was actually checked" do
    with_lookups_stubbed do
      post dashboard_check_path, params: { domain: "https://evil.example.com/login?x=1" }
    end

    assert_response :success
    assert_select "h1", text: "Check Domain"
    assert_match(/Checked the domain evil\.example\.com/, response.body,
                 "silently discarding the path is how a link check became a domain check")
  end

  test "a plain domain gets no normalization note" do
    with_lookups_stubbed do
      post dashboard_check_path, params: { domain: "quiet.example.com" }
    end

    assert_response :success
    assert_no_match(/Checked the domain/, response.body)
  end

  test "the url check keeps the path" do
    with_lookups_stubbed do
      post dashboard_check_url_path, params: { url: "https://evil.example.com/login?x=1" }
    end

    assert_response :success
    assert Phish::Url.exists?(url: "https://evil.example.com/login?x=1"),
           "the whole link is the thing being checked"
  end

  # ===========================================
  # Validation
  # ===========================================

  test "a blank value is rejected with a message" do
    post dashboard_check_path, params: { domain: "" }

    assert_response :success
    assert_select "[role=status]", text: /Enter domain to check/i
  end

  test "an invalid domain is rejected" do
    post dashboard_check_path, params: { domain: "not a domain" }

    assert_response :success
    assert_select "[role=status]", text: /not look like a valid/i
  end

  test "an invalid phone number explains the expected format" do
    post dashboard_check_phone_path, params: { phone: "abc" }

    assert_response :success
    assert_select "[role=status]", text: /international format/i
  end

  # ===========================================
  # A failed check is not a verdict
  # ===========================================

  test "a check that errors says so instead of showing unknown" do
    VerdictService.stub(:check_domain!, ->(_record) { raise Phish::BaseService::ServiceError, "upstream down" }) do
      post dashboard_check_path, params: { domain: "broken.example.com" }
    end

    assert_response :success
    assert_match(/could not be completed/i, response.body)
    assert_no_match(/No source had anything on this yet/, response.body,
                    "an outage must not be reported as a clean lookup")
  end

  test "a genuine no-data result is reported as unknown, not as an error" do
    VerdictService.stub(:check_domain!, ->(record) { record }) do
      post dashboard_check_path, params: { domain: "nodata.example.com" }
    end

    assert_response :success
    assert_no_match(/could not be completed/i, response.body)
  end

  # ===========================================
  # Result rendering
  # ===========================================

  test "an established verdict is shown with its confidence" do
    domain = Phish::Domain.create!(domain: "known.example.com", last_checked_at: 1.minute.ago)
    verdict = Verdict.create!(classification: "phishing", confidence_score: 0.93)
    domain.update!(verdict: verdict)

    post dashboard_check_path, params: { domain: domain.domain }

    assert_response :success
    assert_select "span", text: "Phishing"
    assert_match(/93%/, response.body)
  end

  test "the same classification reads the same way on every check type" do
    %w[email phone].each do |type|
      record =
        if type == "email"
          Phish::Email.create!(email: "bad-#{SecureRandom.hex(3)}@example.com", last_checked_at: 1.minute.ago)
        else
          Phish::PhoneNumber.create!(phone_number: "+1415555#{rand(1000..9999)}", last_checked_at: 1.minute.ago)
        end
      record.update!(verdict: Verdict.create!(classification: "phishing", confidence_score: 0.9))

      path = type == "email" ? dashboard_check_email_path : dashboard_check_phone_path
      key = type == "email" ? :email : :phone
      value = type == "email" ? record.email : record.phone_number

      with_lookups_stubbed { post path, params: { key => value } }

      assert_response :success
      assert_select "span", { text: "Phishing" },
                    "#{type} used to call this Fraudulent or Scam/Fraud instead"
    end
  end

  test "the empty state invites a first check" do
    get dashboard_domain_check_path

    assert_response :success
    assert_match(/Enter domain to check/i, response.body)
  end
end
