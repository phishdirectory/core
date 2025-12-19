# frozen_string_literal: true

require "test_helper"

class Phish::CleandnsTldServiceTest < ActiveSupport::TestCase
  setup do
    @service = Phish::CleandnsTldService.new
  end

  test "sync creates new TLDs from API response" do
    stub_cleandns_response([
      {
        "tlds" => [ "live", "life" ],
        "registrars" => [ "Sav.com, LLC" ],
        "resellers" => []
      }
    ])

    result = @service.sync

    assert result[:success]
    assert_equal 2, result[:created]

    live_tld = Phish::Tld.find_by(name: "live")
    assert live_tld.cleandns_supported?
    assert_includes live_tld.registrars, "Sav.com, LLC"
  end

  test "sync updates existing TLDs" do
    existing = Phish::Tld.create!(name: "com", cleandns_supported: false)

    stub_cleandns_response([
      { "tlds" => [ "com" ], "registrars" => [ "GoDaddy" ], "resellers" => [] }
    ])

    result = @service.sync

    assert result[:success]
    assert_equal 1, result[:updated]

    existing.reload
    assert existing.cleandns_supported?
    assert_includes existing.registrars, "GoDaddy"
  end

  test "sync marks unsupported TLDs as not supported" do
    supported = Phish::Tld.create!(name: "com", cleandns_supported: true)

    stub_cleandns_response([
      { "tlds" => [ "org" ], "registrars" => [], "resellers" => [] }
    ])

    @service.sync

    supported.reload
    assert_not supported.cleandns_supported?
  end

  test "sync aggregates registrars from multiple groups" do
    stub_cleandns_response([
      { "tlds" => [ "com" ], "registrars" => [ "GoDaddy" ], "resellers" => [] },
      { "tlds" => [ "com" ], "registrars" => [ "Namecheap" ], "resellers" => [] }
    ])

    @service.sync

    tld = Phish::Tld.find_by(name: "com")
    assert_includes tld.registrars, "GoDaddy"
    assert_includes tld.registrars, "Namecheap"
  end

  test "tld_supported? returns correct status" do
    Phish::Tld.create!(name: "com", cleandns_supported: true)
    Phish::Tld.create!(name: "xyz", cleandns_supported: false)

    assert @service.tld_supported?("com")
    assert_not @service.tld_supported?("xyz")
    assert_not @service.tld_supported?("nonexistent")
  end

  test "sync handles API errors gracefully" do
    stub_request(:get, "https://api.cleandns.dev/v2/abuse/clients")
      .to_return(status: 500, body: "Internal Server Error")

    result = @service.sync

    assert_not result[:success]
    assert_match(/error/i, result[:error])
  end

  test "sync handles invalid response format" do
    stub_cleandns_response("invalid response")

    result = @service.sync

    assert_not result[:success]
    assert_equal "Invalid response format", result[:error]
  end

  private

  def stub_cleandns_response(data)
    stub_request(:get, "https://api.cleandns.dev/v2/abuse/clients")
      .to_return(
        status: 200,
        body: data.to_json,
        headers: { "Content-Type" => "application/json" }
      )
  end
end
