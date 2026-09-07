# frozen_string_literal: true

require "test_helper"

class TrustedSourceUpsertServiceTest < ActiveSupport::TestCase
  setup do
    @service = create_test_service
    @suffix = SecureRandom.hex(4)
  end

  def upsert(type, entries, **options)
    TrustedSourceUpsertService.call(type: type, entries: entries, service: @service, **options)
  end

  # ===========================================
  # Creating and updating
  # ===========================================

  test "creates a domain that we have never seen and writes its verdict" do
    domain = "source-#{@suffix}.com"

    result = upsert("domain", [ { "domain" => domain, "classification" => "phishing", "confidence" => 0.95 } ])

    assert_equal 1, result[:count]
    assert_equal({ "created" => 1 }, result[:counts])

    record = Phish::Domain.find_by(domain: domain)
    assert_equal "phishing", record.verdict.classification
    assert_in_delta 0.95, record.verdict.confidence_score, 0.001
    assert record.last_checked_at.present?
  end

  test "updates the verdict on a domain we already hold rather than duplicating it" do
    domain = "existing-#{@suffix}.com"
    existing = Phish::Domain.create!(domain: domain)

    result = upsert("domain", [ { "domain" => domain, "classification" => "clean" } ])

    assert_equal "updated", result[:results].first[:status]
    assert_equal 1, Phish::Domain.where(domain: domain).count
    assert_equal "clean", existing.reload.verdict.classification
  end

  test "replaces an earlier verdict in place on a repeat submission" do
    domain = "repeat-#{@suffix}.com"

    first = upsert("domain", [ { "domain" => domain, "classification" => "suspicious" } ])
    second = upsert("domain", [ { "domain" => domain, "classification" => "phishing" } ])

    assert_equal first[:results].first[:verdict_id], second[:results].first[:verdict_id]
    assert_equal "phishing", Phish::Domain.find_by(domain: domain).verdict.classification
  end

  test "names the submitting service on the verdict" do
    domain = "attributed-#{@suffix}.com"

    upsert("domain", [ { "domain" => domain, "classification" => "phishing" } ])

    verdict = Phish::Domain.find_by(domain: domain).verdict
    assert_equal [ "service:#{@service.name}" ], verdict.sources.map { |s| s["name"] }
    assert_equal "service:#{@service.name}", verdict.metadata["trusted_source"]
  end

  test "stores entry metadata on the verdict" do
    domain = "meta-#{@suffix}.com"

    upsert("domain", [ { "domain" => domain, "classification" => "phishing", "metadata" => { "feed" => "daily" } } ])

    assert_equal "daily", Phish::Domain.find_by(domain: domain).verdict.metadata["feed"]
  end

  # ===========================================
  # Every record type
  # ===========================================

  test "upserts urls" do
    url = "https://source-#{@suffix}.com/login"

    upsert("url", [ { "url" => url, "classification" => "phishing" } ])

    assert_equal "phishing", Phish::Url.find_by(url: url).verdict.classification
  end

  test "upserts emails" do
    email = "sender-#{@suffix}@example.com"

    upsert("email", [ { "email" => email, "classification" => "suspicious" } ])

    assert_equal "suspicious", Phish::Email.find_by(email: email).verdict.classification
  end

  test "upserts phone numbers" do
    upsert("phone_number", [ { "phone_number" => "+14155551234", "classification" => "phishing" } ])

    assert_equal "phishing", Phish::PhoneNumber.find_by(phone_number: "+14155551234").verdict.classification
  end

  test "rejects a type it does not handle" do
    assert_raises(TrustedSourceUpsertService::UnknownType) do
      upsert("ip_address", [ "1.1.1.1" ])
    end
  end

  # ===========================================
  # Bare values and request level defaults
  # ===========================================

  test "accepts bare values under a request level classification" do
    domains = [ "bare-a-#{@suffix}.com", "bare-b-#{@suffix}.com" ]

    result = upsert("domain", domains, default_classification: "phishing")

    assert_equal({ "created" => 2 }, result[:counts])
    domains.each do |domain|
      assert_equal "phishing", Phish::Domain.find_by(domain: domain).verdict.classification
    end
  end

  test "defaults confidence to certainty when the source states none" do
    domain = "certain-#{@suffix}.com"

    upsert("domain", [ { "domain" => domain, "classification" => "phishing" } ])

    assert_in_delta 1.0, Phish::Domain.find_by(domain: domain).verdict.confidence_score, 0.001
  end

  test "an entry level classification wins over the request level one" do
    domain = "override-#{@suffix}.com"

    upsert("domain", [ { "domain" => domain, "classification" => "clean" } ], default_classification: "phishing")

    assert_equal "clean", Phish::Domain.find_by(domain: domain).verdict.classification
  end

  test "normalizes a domain sent as a url" do
    result = upsert("domain", [ "HTTPS://Normalize-#{@suffix}.COM/path?a=b" ], default_classification: "phishing")

    assert_equal "created", result[:results].first[:status]
    assert Phish::Domain.exists?(domain: "normalize-#{@suffix}.com")
  end

  # ===========================================
  # Validation
  # ===========================================

  test "reports a malformed value without failing the rest of the batch" do
    good = "good-#{@suffix}.com"

    result = upsert("domain", [ "not a domain", good ], default_classification: "phishing")

    assert_equal 1, result[:counts]["invalid"]
    assert_equal 1, result[:counts]["created"]
    assert Phish::Domain.exists?(domain: good)
  end

  test "refuses a value that is not a scalar" do
    result = upsert("domain", [ { "domain" => { "nested" => "object" }, "classification" => "phishing" } ])

    assert_equal "invalid", result[:results].first[:status]
  end

  test "refuses an entry that carries no value at all" do
    result = upsert("domain", [ { "classification" => "phishing" } ])

    assert_equal "invalid", result[:results].first[:status]
  end

  test "refuses a classification a source may not assign" do
    %w[unknown protected nonsense].each do |classification|
      result = upsert("domain", [ { "domain" => "class-#{@suffix}.com", "classification" => classification } ])

      assert_equal "invalid", result[:results].first[:status], "expected #{classification} to be refused"
    end

    assert_not Phish::Domain.exists?(domain: "class-#{@suffix}.com")
  end

  test "refuses an entry that states no classification at all" do
    result = upsert("domain", [ "noclass-#{@suffix}.com" ])

    assert_equal "invalid", result[:results].first[:status]
  end

  test "refuses a confidence outside 0 to 1" do
    result = upsert("domain", [ { "domain" => "conf-#{@suffix}.com", "classification" => "phishing", "confidence" => 4 } ])

    assert_equal "invalid", result[:results].first[:status]
    assert_not Phish::Domain.exists?(domain: "conf-#{@suffix}.com")
  end

  test "refuses metadata that is not an object" do
    result = upsert("domain", [ { "domain" => "badmeta-#{@suffix}.com", "classification" => "phishing", "metadata" => "a string" } ])

    assert_equal "invalid", result[:results].first[:status]
  end

  test "refuses metadata larger than the cap" do
    oversized = { "blob" => "x" * (TrustedSourceUpsertService::MAX_METADATA_BYTES + 1) }

    result = upsert("domain", [ { "domain" => "bigmeta-#{@suffix}.com", "classification" => "phishing", "metadata" => oversized } ])

    assert_equal "invalid", result[:results].first[:status]
  end

  # ===========================================
  # Protection
  # ===========================================

  test "refuses to classify a protected domain" do
    domain = "protected-#{@suffix}.com"
    admin = create_test_user(access_level: :admin)
    Phish::Protection.create!(protectable_type: "Phish::Domain", protectable_value: domain, protected_by: admin)

    result = upsert("domain", [ { "domain" => domain, "classification" => "phishing" } ])

    assert_equal "rejected", result[:results].first[:status]
    assert_not Phish::Domain.exists?(domain: domain)
  end

  test "leaves an existing verdict alone when the value is protected" do
    domain = "protected-existing-#{@suffix}.com"
    admin = create_test_user(access_level: :admin)
    record = Phish::Domain.create!(domain: domain)
    VerdictService.apply_trusted_source!(
      record, classification: "clean", confidence: 1.0, source: "seed"
    )
    Phish::Protection.create!(protectable_type: "Phish::Domain", protectable_value: domain, protected_by: admin)

    upsert("domain", [ { "domain" => domain, "classification" => "phishing" } ])

    assert_equal "clean", record.reload.verdict.classification
  end
end
