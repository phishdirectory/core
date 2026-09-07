# frozen_string_literal: true

require "test_helper"

class AdminIokIndicatorsTest < ActionDispatch::IntegrationTest
  setup do
    Iok::Indicator.with_discarded.delete_all
    Iok::RuleSet.reset!
    @indicator = create_indicator
  end

  teardown { Iok::RuleSet.reset! }

  def create_indicator(slug: "example-kit", **attrs)
    Iok::Indicator.create!({
      slug: slug,
      title: "Example Kit",
      content_digest: SecureRandom.hex(8),
      tags: %w[kit target.example],
      reference_urls: [ "https://urlscan.io/result/example/" ],
      source_url: "https://github.com/phish-report/IOK/blob/main/indicators/example-kit.yml",
      synced_at: Time.current,
      detection: { "marker" => { "html|contains" => "kit-marker" }, "condition" => "marker" }
    }.merge(attrs))
  end

  def sign_in_admin
    sign_in(create_test_user(access_level: :admin))
  end

  test "an admin sees the indicator list" do
    sign_in_admin

    get admin_iok_indicators_path

    assert_response :success
    assert_match "Example Kit", response.body
  end

  test "a regular user is turned away" do
    sign_in(create_test_user)

    get admin_iok_indicators_path

    assert_redirected_to root_path
  end

  test "the list can be filtered by tag" do
    create_indicator(slug: "other-kit", title: "Other Kit", tags: %w[malware])
    sign_in_admin

    get admin_iok_indicators_path(tag: "target.example")

    assert_response :success
    assert_match "Example Kit", response.body
    assert_no_match "Other Kit", response.body
  end

  test "the list can be searched by title" do
    create_indicator(slug: "other-kit", title: "Other Kit")
    sign_in_admin

    get admin_iok_indicators_path(q: "Other")

    assert_response :success
    assert_match "Other Kit", response.body
    assert_no_match ">Example Kit<", response.body
  end

  test "an admin sees the detection block on the detail page" do
    sign_in_admin

    get admin_iok_indicator_path(@indicator)

    assert_response :success
    assert_match "kit-marker", response.body
    assert_match @indicator.slug, response.body
  end

  # Disabling one rule is the lever for a rule that starts producing false
  # positives, so it has to take effect without waiting for a sync.
  test "an admin can disable and re-enable an indicator" do
    sign_in_admin

    post disable_admin_iok_indicator_path(@indicator)

    assert_redirected_to admin_iok_indicator_path(@indicator)
    assert_not @indicator.reload.enabled?
    assert_predicate Iok::RuleSet.current, :empty?

    post enable_admin_iok_indicator_path(@indicator)

    assert @indicator.reload.enabled?
    assert_equal 1, Iok::RuleSet.current.size
  end

  test "an admin can queue a sync" do
    sign_in_admin

    assert_enqueued_with(job: IokSyncJob) do
      post sync_admin_iok_indicators_path
    end

    assert_redirected_to admin_iok_indicators_path
  end

  test "a regular user cannot disable an indicator" do
    sign_in(create_test_user)

    post disable_admin_iok_indicator_path(@indicator)

    assert_redirected_to root_path
    assert @indicator.reload.enabled?
  end
end
