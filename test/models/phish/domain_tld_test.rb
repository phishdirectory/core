# frozen_string_literal: true

require "test_helper"

class Phish::DomainTldTest < ActiveSupport::TestCase
  test "auto-associates TLD on create" do
    domain = Phish::Domain.create!(domain: "example.com")

    assert_not_nil domain.tld
    assert_equal "com", domain.tld.name
  end

  test "auto-associates TLD on domain change" do
    domain = Phish::Domain.create!(domain: "example.com")
    original_tld = domain.tld

    domain.update!(domain: "example.org")

    assert_not_equal original_tld.id, domain.tld_id
    assert_equal "org", domain.tld.name
  end

  test "tld_name helper returns TLD name" do
    domain = Phish::Domain.create!(domain: "example.co.uk")
    assert_equal "co.uk", domain.tld_name
  end

  test "with_tld scope returns domains with TLD" do
    with_tld = Phish::Domain.create!(domain: "example.com")
    without_tld = Phish::Domain.new(domain: "example.org")
    without_tld.save(validate: false)
    without_tld.update_column(:tld_id, nil)

    assert_includes Phish::Domain.with_tld, with_tld
    assert_not_includes Phish::Domain.with_tld, without_tld
  end

  test "without_tld scope returns domains without TLD" do
    with_tld = Phish::Domain.create!(domain: "example.com")
    without_tld = Phish::Domain.new(domain: "example.org")
    without_tld.save(validate: false)
    without_tld.update_column(:tld_id, nil)

    assert_includes Phish::Domain.without_tld, without_tld
    assert_not_includes Phish::Domain.without_tld, with_tld
  end

  test "cleandns_reportable scope filters by TLD support" do
    supported_tld = Phish::Tld.create!(name: "info", cleandns_supported: true)
    unsupported_tld = Phish::Tld.create!(name: "xyz", cleandns_supported: false)

    reportable_domain = Phish::Domain.create!(domain: "phish.info")
    unreportable_domain = Phish::Domain.create!(domain: "phish.xyz")

    reportable = Phish::Domain.cleandns_reportable

    assert_includes reportable, reportable_domain
    assert_not_includes reportable, unreportable_domain
  end

  test "tld_cleandns_supported? delegation works" do
    tld = Phish::Tld.create!(name: "info", cleandns_supported: true)
    domain = Phish::Domain.create!(domain: "example.info")

    assert domain.tld_cleandns_supported?
  end

  test "tld_cleandns_supported? returns nil for domain without TLD" do
    domain = Phish::Domain.new(domain: "example.com")
    domain.save(validate: false)
    domain.update_column(:tld_id, nil)

    assert_nil domain.tld_cleandns_supported?
  end
end
