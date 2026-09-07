# frozen_string_literal: true

require "test_helper"

# The public XARF utility. The point of the page is that an ordinary reporter
# never has to write JSON, so these tests care about what the page says as much
# as what it generates.
class XarfToolTest < ActionDispatch::IntegrationTest
  setup do
    @user = create_test_user
  end

  teardown do
    Flipper.disable(:auto_reporting)
  end

  # The check calls external threat intelligence services synchronously. Tests
  # that are about the page, not the lookup, stub them out.
  def with_lookups_stubbed(&block)
    noop = ->(record) { record }
    VerdictService.stub(:check_domain!, noop) do
      VerdictService.stub(:check_url!, noop, &block)
    end
  end

  # Opening a case looks up WHOIS/RDAP for the domain, which is a real network
  # call. Nothing here is testing that lookup.
  class NullLookup
    def lookup(_domain) = nil
  end

  def with_domain_lookup_stubbed(&block)
    Report::DomainLookupService.stub(:new, ->(**_kwargs) { NullLookup.new }, &block)
  end

  def classify!(record, classification, confidence)
    record.update!(
      verdict: Verdict.create!(
        classification: classification,
        confidence_score: confidence,
        sources: [ { "name" => "walshy", "result" => "phishing" } ]
      ),
      last_checked_at: Time.current
    )
  end

  def phishing_url(url = "https://evil-#{SecureRandom.hex(4)}.example.com/login", confidence: 0.95)
    record = Phish::Url.find_or_create_by_natural_key!(url: url)
    classify!(record, "phishing", confidence)
    record
  end

  # ===========================================
  # The page is public
  # ===========================================

  test "anyone can open the generator without signing in" do
    get xarf_path

    assert_response :success
    assert_select "h1", text: /Report abuse without writing JSON/
    assert_select "form[action=?]", xarf_path
  end

  test "the input has a real label, not just a placeholder" do
    get xarf_path

    assert_select "label[for=?]", "value", { minimum: 1 },
                  "the link field has no label"
  end

  # Turbo Drive throws away a 200 HTML response to a form post ("Form responses
  # must redirect to another location"), so the page silently never updated in
  # a real browser while every test here still passed. These actions answer
  # with the result rather than a redirect, so the forms have to opt out.
  test "the forms opt out of turbo, which would discard the response" do
    record = phishing_url

    with_lookups_stubbed do
      post xarf_path, params: { type: "url", value: record.url }
    end

    assert_select "form[data-turbo='false'][action=?]", xarf_path, { count: 1 },
                  "the generate form would have its response discarded by Turbo"
  end

  test "the home page links to the generator" do
    get root_path

    assert_response :success
    assert_select "a[href=?]", xarf_path
  end

  # ===========================================
  # Only malicious things produce a report
  # ===========================================

  test "a confirmed phishing url produces a xarf report" do
    record = phishing_url

    with_lookups_stubbed do
      post xarf_path, params: { type: "url", value: record.url }
    end

    assert_response :success
    assert_match(/XARF v4 JSON/, response.body)
    assert_match(/xarf_version/, response.body)
    assert_match(/&quot;4\.0\.0&quot;/, response.body)
    assert_match(/source_identifier/, response.body)
  end

  test "a clean domain produces no report and says why" do
    record = Phish::Domain.find_or_create_by_natural_key!(domain: "safe-#{SecureRandom.hex(4)}.example.com")
    classify!(record, "clean", 0.9)

    with_lookups_stubbed do
      post xarf_path, params: { type: "domain", value: record.domain }
    end

    assert_response :success
    assert_match(/believe it is legitimate/, response.body)
    assert_no_match(/xarf_version/, response.body)
  end

  test "an unrecognised domain says nothing is known rather than that it is fine" do
    record = Phish::Domain.find_or_create_by_natural_key!(domain: "quiet-#{SecureRandom.hex(4)}.example.com")
    classify!(record, "unknown", 0.0)

    with_lookups_stubbed do
      post xarf_path, params: { type: "domain", value: record.domain }
    end

    assert_response :success
    assert_match(/no source has anything on it yet/, response.body)
    assert_no_match(/believe it is legitimate/, response.body)
  end

  # An outage and a genuine no-data answer must not render the same way, or an
  # unreachable source reads as a clean bill of health.
  test "a source outage is reported as an outage, not as a verdict" do
    record = Phish::Url.find_or_create_by_natural_key!(url: "https://down-#{SecureRandom.hex(4)}.example.com/")

    VerdictService.stub(:check_url!, ->(_r) { raise StandardError, "upstream is down" }) do
      post xarf_path, params: { type: "url", value: record.url }
    end

    assert_response :success
    assert_match(/could not reach our threat intelligence sources/, response.body)
    assert_match(/not a verdict/, response.body)
  end

  test "an unparseable value is rejected without touching any source" do
    VerdictService.stub(:check_url!, ->(_r) { raise "should not be called" }) do
      post xarf_path, params: { type: "url", value: "not a url at all" }
    end

    assert_response :success
    assert_match(/does not look like a link or a domain/, response.body)
  end

  test "an empty submission asks for a value" do
    post xarf_path, params: { type: "url", value: "" }

    assert_response :success
    assert_match(/Enter a link or a domain/, response.body)
  end

  # ===========================================
  # Download
  # ===========================================

  test "a report downloads as a json attachment" do
    record = phishing_url

    with_lookups_stubbed do
      get xarf_download_path(type: "url", value: record.url)
    end

    assert_response :success
    assert_equal "application/json", response.media_type
    assert_match(/attachment/, response.headers["Content-Disposition"])

    payload = JSON.parse(response.body)
    assert_equal "4.0.0", payload["xarf_version"]
    assert_equal "phishing", payload["type"]
    assert_equal "content", payload["category"]
  end

  test "downloading something that is not reportable redirects instead of sending an empty file" do
    record = Phish::Domain.find_or_create_by_natural_key!(domain: "fine-#{SecureRandom.hex(4)}.example.com")
    classify!(record, "clean", 0.9)

    with_lookups_stubbed do
      get xarf_download_path(type: "domain", value: record.domain)
    end

    assert_redirected_to xarf_path
  end

  # ===========================================
  # Submission needs an account
  # ===========================================

  test "a signed-out visitor is offered sign-in rather than a send button" do
    record = phishing_url

    with_lookups_stubbed do
      post xarf_path, params: { type: "url", value: record.url }
    end

    assert_response :success
    assert_select "form[action=?]", xarf_submit_path, false,
                  "a signed-out visitor was shown the send form"
    assert_select "a[href=?]", login_path
  end

  test "posting a submission while signed out is refused" do
    record = phishing_url

    with_lookups_stubbed do
      post xarf_submit_path, params: { type: "url", value: record.url }
    end

    assert_redirected_to login_path
    assert_equal 0, Report::Case.count
  end

  test "a signed-in user sees the send form" do
    record = phishing_url
    sign_in(@user)

    with_lookups_stubbed do
      post xarf_path, params: { type: "url", value: record.url }
    end

    assert_response :success
    assert_select "form[data-turbo='false'][action=?]", xarf_submit_path
  end

  # ===========================================
  # Submission
  # ===========================================

  test "a signed-in user can open a case for a confirmed phishing url" do
    record = phishing_url
    sign_in(@user)
    Flipper.enable(:auto_reporting)

    assert_difference -> { Report::Case.count }, 1 do
      with_lookups_stubbed do
        with_domain_lookup_stubbed do
          post xarf_submit_path, params: { type: "url", value: record.url }
        end
      end
    end

    assert_response :success
    assert_match(/Report sent/, response.body)

    report_case = Report::Case.last
    assert_equal record, report_case.reportable
    assert_match(/#{report_case.case_number}/, response.body)
  end

  test "submitting something already reported points at the open case" do
    record = phishing_url
    sign_in(@user)
    Flipper.enable(:auto_reporting)

    existing = Report::Case.create!(
      reportable: record,
      verdict_snapshot: record.verdict,
      confidence_at_creation: 0.95
    )

    assert_no_difference -> { Report::Case.count } do
      with_lookups_stubbed do
        post xarf_submit_path, params: { type: "url", value: record.url }
      end
    end

    assert_response :success
    assert_match(/already reported/, response.body)
    assert_match(/#{existing.case_number}/, response.body)
  end

  test "a low confidence verdict explains why we will not send it" do
    record = phishing_url(confidence: 0.4)
    sign_in(@user)
    Flipper.enable(:auto_reporting)

    assert_no_difference -> { Report::Case.count } do
      with_lookups_stubbed do
        post xarf_submit_path, params: { type: "url", value: record.url }
      end
    end

    assert_response :success
    assert_match(/below the threshold/, response.body)
    # The report itself is still there to download and send by hand.
    assert_match(/xarf_version/, response.body)
  end

  test "the reporting kill switch is honoured" do
    record = phishing_url
    sign_in(@user)
    Flipper.disable(:auto_reporting)

    assert_no_difference -> { Report::Case.count } do
      with_lookups_stubbed do
        post xarf_submit_path, params: { type: "url", value: record.url }
      end
    end

    assert_response :success
    assert_match(/Automatic reporting is paused/, response.body)
  end
end
