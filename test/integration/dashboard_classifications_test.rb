# frozen_string_literal: true

require "test_helper"

# The controller has always loaded a queue and a recent-classification list,
# and the page has never rendered either, so a trusted user could not see what
# was waiting or what they had already done.
class DashboardClassificationsTest < ActionDispatch::IntegrationTest
  setup do
    @user = create_test_user(access_level: :trusted)
    sign_in(@user)
  end

  def pending_domain(name = "queue-#{SecureRandom.hex(4)}.com")
    domain = Phish::Domain.create!(domain: name, last_checked_at: 1.hour.ago)
    domain.update!(verdict: Verdict.create!(classification: "phishing", confidence_score: 0.9))
    domain
  end

  test "the page renders for a trusted user" do
    get dashboard_classifications_path

    assert_response :success
  end

  test "a non-trusted user cannot reach it" do
    # magic_link_login redirects when already authenticated, so signing in as
    # a second user only works after signing the first one out.
    delete logout_path
    sign_in(create_test_user)

    get dashboard_classifications_path

    assert_response :redirect
  end

  test "the queue lists what is waiting" do
    domain = pending_domain

    get dashboard_classifications_path

    assert_response :success
    assert_select "h2", text: /Next in the queue/
    assert_match(/#{Regexp.escape(domain.domain)}/, response.body,
                 "the queue was computed by the controller and never rendered")
  end

  test "a queued item links to its classification page" do
    domain = pending_domain

    get dashboard_classifications_path

    assert_select "a[href=?]", dashboard_classification_path(type: "domain", id: domain.public_id)
  end

  test "recent classifications are listed" do
    domain = pending_domain
    Scam::Classification.create!(
      classifiable: domain,
      user: @user,
      scam_category: Scam.taxonomy_for_select.first[:value],
      scam_subcategory: Scam.taxonomy_for_select.first[:subcategories].first[:value]
    )

    get dashboard_classifications_path

    assert_response :success
    assert_select "h2", text: /Your recent classifications/
    assert_match(/#{Regexp.escape(domain.domain)}/, response.body)
  end

  test "someone with no classifications sees an empty state, not a blank panel" do
    get dashboard_classifications_path

    assert_response :success
    assert_match(/You have not classified anything yet/, response.body)
  end
end
