# frozen_string_literal: true

require "test_helper"
require "rubygems/package"
require "stringio"
require "zlib"

class Iok::SyncServiceTest < ActiveSupport::TestCase
  setup do
    Iok::Indicator.with_discarded.delete_all
    Iok::RuleSet.reset!
  end

  teardown { Iok::RuleSet.reset! }

  RULE = <<~YAML
    title: Example Phishing Kit
    description: |
      A kit used in tests.
    references:
      - https://urlscan.io/result/example/
    detection:
      marker:
        html|contains: 'name="spox" value="fuck_you_bot"'
      condition: marker
    tags:
      - kit
      - target.example
  YAML

  # Builds the gzipped tar that codeload serves for the upstream repository.
  def archive(files)
    tar = StringIO.new(+"", "w+b")

    Gem::Package::TarWriter.new(tar) do |writer|
      files.each do |name, contents|
        writer.add_file(name, 0o644) { |io| io.write(contents) }
      end
    end

    gzipped = StringIO.new(+"", "w+b")
    Zlib::GzipWriter.wrap(gzipped) { |gz| gz.write(tar.string) }
    gzipped.string
  end

  def indicator_files(count, contents: RULE)
    (1..count).to_h { |i| [ "IOK-main/indicators/kit-#{i}.yml", contents ] }
  end

  def stub_archive(files)
    stub_request(:get, Iok::SyncService::ARCHIVE_URL)
      .to_return(status: 200, body: archive(files), headers: { "Content-Type" => "application/gzip" })
  end

  def sync
    Iok::SyncService.new.sync
  end

  # ===========================================
  # Happy path
  # ===========================================

  test "creates an indicator for each rule in the archive" do
    stub_archive(indicator_files(60))

    result = sync

    assert result[:success]
    assert_equal 60, result[:created]
    assert_equal 60, Iok::Indicator.count
  end

  test "stores the parsed rule metadata" do
    stub_archive(indicator_files(60))
    sync

    indicator = Iok::Indicator.find_by!(slug: "kit-1")

    assert_equal "Example Phishing Kit", indicator.title
    assert_equal "A kit used in tests.\n", indicator.description
    assert_equal [ "https://urlscan.io/result/example/" ], indicator.reference_urls
    assert_equal %w[kit target.example], indicator.tags
    assert_equal "marker", indicator.detection["condition"]
    assert_equal "https://github.com/phish-report/IOK/blob/main/indicators/kit-1.yml",
                 indicator.source_url
    assert indicator.enabled?
    assert indicator.synced_at.present?
  end

  test "ignores files outside the indicators directory" do
    files = indicator_files(60).merge(
      "IOK-main/README.md" => "# IOK",
      "IOK-main/logsource.yml" => "title: Sigma config"
    )
    stub_archive(files)

    assert_equal 60, sync[:created]
  end

  # ===========================================
  # Repeated syncs
  # ===========================================

  test "an unchanged rule is left alone" do
    stub_archive(indicator_files(60))
    sync

    before = Iok::Indicator.find_by!(slug: "kit-1").updated_at
    result = sync

    assert_equal 60, result[:unchanged]
    assert_equal 0, result[:updated]
    assert_equal before, Iok::Indicator.find_by!(slug: "kit-1").reload.updated_at
  end

  test "a changed rule is updated" do
    stub_archive(indicator_files(60))
    sync

    stub_archive(indicator_files(60, contents: RULE.sub("Example Phishing Kit", "Renamed Kit")))
    result = sync

    assert_equal 60, result[:updated]
    assert_equal "Renamed Kit", Iok::Indicator.find_by!(slug: "kit-1").title
  end

  test "an indicator withdrawn upstream is discarded" do
    stub_archive(indicator_files(60))
    sync

    stub_archive(indicator_files(59))
    result = sync

    assert_equal 1, result[:removed]
    assert_equal 59, Iok::Indicator.count
    assert Iok::Indicator.with_discarded.find_by(slug: "kit-60").discarded?
  end

  test "an indicator restored upstream reuses its record" do
    stub_archive(indicator_files(60))
    sync
    original_id = Iok::Indicator.find_by!(slug: "kit-60").id

    stub_archive(indicator_files(59))
    sync

    stub_archive(indicator_files(60))
    sync

    indicator = Iok::Indicator.find_by!(slug: "kit-60")
    assert_equal original_id, indicator.id
    assert_equal 60, Iok::Indicator.count
  end

  # ===========================================
  # Bad input
  # ===========================================

  test "skips a rule whose detection block does not compile" do
    broken = "title: Broken\ndetection:\n  marker:\n    body|contains: 'x'\n  condition: marker\n"
    stub_archive(indicator_files(60).merge("IOK-main/indicators/broken.yml" => broken))

    result = sync

    assert result[:success]
    assert_equal 1, result[:invalid]
    assert_nil Iok::Indicator.find_by(slug: "broken")
  end

  test "skips a rule that is not valid yaml" do
    stub_archive(indicator_files(60).merge("IOK-main/indicators/bad.yml" => "title: [unclosed\n"))

    assert sync[:success]
    assert_nil Iok::Indicator.find_by(slug: "bad")
  end

  # A truncated download must not look like an upstream purge and discard the
  # whole corpus.
  test "refuses an archive holding implausibly few indicators" do
    stub_archive(indicator_files(60))
    sync

    stub_archive(indicator_files(2))
    result = sync

    assert_not result[:success]
    assert_match(/expected at least/, result[:error])
    assert_equal 60, Iok::Indicator.count
  end

  test "reports a download failure without touching existing rows" do
    stub_archive(indicator_files(60))
    sync

    stub_request(:get, Iok::SyncService::ARCHIVE_URL).to_return(status: 500, body: "")
    result = sync

    assert_not result[:success]
    assert_equal 60, Iok::Indicator.count
  end

  test "reports an archive that is not gzip" do
    stub_request(:get, Iok::SyncService::ARCHIVE_URL).to_return(status: 200, body: "not a tarball")

    result = sync

    assert_not result[:success]
    assert_match(/could not read archive/, result[:error])
  end

  test "does not check domains or urls" do
    service = Iok::SyncService.new

    assert_raises(NotImplementedError) { service.check_domain("example.com") }
    assert_raises(NotImplementedError) { service.check_url("https://example.com") }
  end
end
