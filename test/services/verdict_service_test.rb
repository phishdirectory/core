# frozen_string_literal: true

require "test_helper"

class VerdictServiceTest < ActiveSupport::TestCase
  setup do
    @domain = Phish::Domain.create!(domain: "verdict-#{SecureRandom.hex(4)}.com")
  end

  def result_for(verdict, confidence: 0.9, reason: nil)
    details = { service_results: [ { service: "fake", verdict: verdict, confidence: confidence } ] }
    details[:reason] = reason if reason
    { verdict: verdict, confidence: confidence, details: details }
  end

  # ===========================================
  # Trusted source submissions
  # ===========================================

  test "apply_trusted_source! records the classification the source supplied" do
    verdict = VerdictService.apply_trusted_source!(
      @domain, classification: "phishing", confidence: 0.8, source: "service:partner"
    )

    assert_equal "phishing", verdict.classification
    assert_in_delta 0.8, verdict.confidence_score, 0.001
    assert_equal "service:partner", verdict.metadata["trusted_source"]
    assert_equal [ "service:partner" ], verdict.sources.map { |s| s["name"] }

    @domain.reload
    assert_equal verdict, @domain.verdict
    assert @domain.last_checked_at.present?
  end

  test "apply_trusted_source! replaces an aggregator verdict rather than adding one" do
    aggregated = VerdictService.update_verdict!(@domain, result_for("clean"))
    trusted = VerdictService.apply_trusted_source!(
      @domain.reload, classification: "phishing", confidence: 1.0, source: "service:partner"
    )

    assert_equal aggregated.id, trusted.id
    assert_equal "phishing", trusted.classification
    assert_not trusted.metadata.key?("service_results")
  end

  # ===========================================
  # Creating and updating
  # ===========================================

  test "creates a verdict for a record that has none" do
    verdict = VerdictService.update_verdict!(@domain, result_for("phishing"))

    assert_equal "phishing", verdict.classification
    assert_in_delta 0.9, verdict.confidence_score, 0.001

    @domain.reload
    assert_equal verdict, @domain.verdict
    assert @domain.last_checked_at.present?
  end

  test "updates the existing verdict in place rather than creating a second one" do
    first = VerdictService.update_verdict!(@domain, result_for("suspicious", confidence: 0.5))
    second = VerdictService.update_verdict!(@domain.reload, result_for("phishing", confidence: 0.95))

    assert_equal first.id, second.id
    assert_equal "phishing", second.classification
    assert_in_delta 0.95, second.confidence_score, 0.001
  end

  test "stores service results as sources and the full details as metadata" do
    verdict = VerdictService.update_verdict!(@domain, result_for("clean", confidence: 0.8))

    assert_equal 1, verdict.sources.size
    assert_equal "fake", verdict.sources.first["service"]
    assert verdict.metadata.key?("service_results")
  end

  test "records unknown when the record has no verdict yet" do
    verdict = VerdictService.update_verdict!(@domain, result_for("unknown", confidence: 0.0))

    assert_equal "unknown", verdict.classification
    assert_equal verdict, @domain.reload.verdict
  end

  # ===========================================
  # Downgrade protection
  #
  # An outage makes every service fail at once, which the aggregator reports as
  # "unknown". That must never erase a verdict we already established.
  # ===========================================

  test "keeps an existing phishing verdict when a check returns unknown" do
    VerdictService.update_verdict!(@domain, result_for("phishing", confidence: 0.95))
    checked_at = @domain.reload.last_checked_at

    kept = VerdictService.update_verdict!(
      @domain,
      result_for("unknown", confidence: 0.0, reason: "All 8 service(s) failed")
    )

    assert_equal "phishing", kept.classification
    assert_in_delta 0.95, kept.confidence_score, 0.001

    @domain.reload
    assert_equal "phishing", @domain.verdict.classification
    assert_equal checked_at.to_i, @domain.last_checked_at.to_i,
                 "a check that learned nothing must not count as a successful check"
  end

  test "keeps suspicious, clean and protected verdicts from being erased by unknown" do
    %w[suspicious clean protected].each do |classification|
      domain = Phish::Domain.create!(domain: "keep-#{SecureRandom.hex(4)}.com")
      VerdictService.update_verdict!(domain, result_for(classification, confidence: 0.7))

      VerdictService.update_verdict!(domain, result_for("unknown", confidence: 0.0))

      assert_equal classification, domain.reload.verdict.classification,
                   "#{classification} should survive an unknown result"
    end
  end

  test "allows unknown to replace an existing unknown" do
    VerdictService.update_verdict!(@domain, result_for("unknown", confidence: 0.0))

    verdict = VerdictService.update_verdict!(@domain.reload, result_for("unknown", confidence: 0.0))

    assert_equal "unknown", verdict.classification
  end

  test "a real verdict still replaces an existing one in either direction" do
    VerdictService.update_verdict!(@domain, result_for("phishing", confidence: 0.95))

    verdict = VerdictService.update_verdict!(@domain.reload, result_for("clean", confidence: 0.85))

    assert_equal "clean", verdict.classification,
                 "only unknown is blocked; a real reassessment must still apply"
  end

  test "downgrade_to_unknown? identifies exactly the blocked case" do
    assert_not VerdictService.downgrade_to_unknown?(@domain, result_for("unknown")),
               "no existing verdict means nothing to protect"

    VerdictService.update_verdict!(@domain, result_for("phishing"))

    assert VerdictService.downgrade_to_unknown?(@domain.reload, result_for("unknown"))
    assert_not VerdictService.downgrade_to_unknown?(@domain.reload, result_for("clean"))
  end
end
