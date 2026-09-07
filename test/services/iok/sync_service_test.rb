# frozen_string_literal: true

require "test_helper"
require "rubygems/package"
require "tmpdir"
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

  # The real db/iok/local rules take part in every sync, so every count below
  # would move whenever somebody adds one. Each sync therefore runs against a
  # temporary local directory, empty unless the test passes rules in.
  def sync(local: {})
    with_local_rules(local) { Iok::SyncService.new.sync }
  end

  def with_local_rules(files, &block)
    Dir.mktmpdir do |dir|
      files.each { |name, contents| File.write(File.join(dir, name), contents) }

      Iok::SyncService.stub(:local_rule_path, Pathname.new(dir), &block)
    end
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

  # ===========================================
  # Local rules
  # ===========================================

  LOCAL_RULE = <<~YAML
    title: Local Test Kit
    description: A rule we wrote ourselves.
    references:
      - https://urlscan.io/result/local/
    detection:
      marker:
        html|contains: "local-kit-marker"
      condition: marker
    tags:
      - kit
  YAML

  test "loads rules from the local directory" do
    stub_archive(indicator_files(60))

    result = sync(local: { "local-test-kit.yml" => LOCAL_RULE })

    assert result[:success]
    assert_equal 61, result[:created]

    indicator = Iok::Indicator.find_by!(slug: "local-test-kit")
    assert_equal "local", indicator.source
    assert_nil indicator.source_url
  end

  # The bug this whole source column exists to prevent.
  test "the upstream pass does not discard local rules" do
    stub_archive(indicator_files(60))
    sync(local: { "local-test-kit.yml" => LOCAL_RULE })

    result = sync(local: { "local-test-kit.yml" => LOCAL_RULE })

    assert_equal 0, result[:removed]
    assert_predicate Iok::Indicator.find_by!(slug: "local-test-kit"), :kept?
  end

  test "the local pass does not discard upstream rules" do
    stub_archive(indicator_files(60))
    sync(local: { "local-test-kit.yml" => LOCAL_RULE })

    assert_equal 60, Iok::Indicator.upstream.count
    assert_equal 1, Iok::Indicator.local.count
  end

  test "a local rule removed from the directory is discarded" do
    stub_archive(indicator_files(60))
    sync(local: { "local-test-kit.yml" => LOCAL_RULE })

    result = sync

    assert_equal 1, result[:removed]
    assert_equal 60, Iok::Indicator.count
  end

  # A GitHub outage must not stop a rule we wrote from reaching the database.
  test "local rules still land when the archive download fails" do
    stub_request(:get, Iok::SyncService::ARCHIVE_URL).to_return(status: 500, body: "")

    result = sync(local: { "local-test-kit.yml" => LOCAL_RULE })

    assert_not result[:success]
    assert_equal 1, result[:created]
    assert_predicate Iok::Indicator.find_by(slug: "local-test-kit"), :present?
  end

  test "skips a local rule that does not compile" do
    broken = "title: Broken\ndetection:\n  marker:\n    body|contains: 'x'\n  condition: marker\n"
    stub_archive(indicator_files(60))

    result = sync(local: { "broken.yml" => broken })

    assert_equal 1, result[:invalid]
    assert_nil Iok::Indicator.find_by(slug: "broken")
  end

  test "local rules are matched alongside upstream ones" do
    stub_archive(indicator_files(60))
    sync(local: { "local-test-kit.yml" => LOCAL_RULE })

    matches = Iok::RuleSet.current.matches("html" => [ "a local-kit-marker here" ])

    assert_equal [ "local-test-kit" ], matches.map(&:slug)
  end
end
