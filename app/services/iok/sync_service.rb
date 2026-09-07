# frozen_string_literal: true

require "rubygems/package"
require "stringio"
require "zlib"

module Iok
  # Syncs the IOK indicator corpus from phish-report/IOK.
  #
  # The rules are ODbL-1.0 licensed and live as one YAML file per indicator
  # under `indicators/`. We pull the whole repository as a single gzipped tar
  # rather than asking the GitHub API for each of the few hundred files, which
  # keeps the job to one request and stays clear of the unauthenticated API
  # rate limit.
  class SyncService < Phish::BaseService
    REPOSITORY = "phish-report/IOK"
    REPOSITORY_URL = "https://github.com/phish-report/IOK"
    ARCHIVE_URL = "https://codeload.github.com/phish-report/IOK/tar.gz/refs/heads/main"
    LICENSE = "ODbL-1.0"

    # Entries look like `IOK-main/indicators/1password-191635.yml`.
    INDICATOR_ENTRY = %r{\A[^/]+/indicators/(?<slug>[^/]+)\.ya?ml\z}i

    # Guards against a truncated or redirected download quietly discarding the
    # whole corpus. The repository has carried well over a hundred indicators
    # for years, so anything below this is a bad archive, not an upstream purge.
    MINIMUM_EXPECTED = 50

    ARCHIVE_TIMEOUT = 60

    rate_limit :hourly, requests: 10, period: 1.hour

    def check_domain(_domain)
      raise NotImplementedError, "#{service_name} does not check domains"
    end

    def check_url(_url)
      raise NotImplementedError, "#{service_name} does not check URLs"
    end

    # @return [Hash] :success plus per-outcome counts
    def sync
      log_info("Syncing IOK indicators from #{REPOSITORY}...")

      documents = with_rate_limit { parse_archive(download_archive) }

      if documents.size < MINIMUM_EXPECTED
        return failure("archive held only #{documents.size} indicators, expected at least #{MINIMUM_EXPECTED}")
      end

      stats = persist(documents)
      Iok::RuleSet.reset!

      log_info(
        "IOK sync complete: #{stats[:created]} created, #{stats[:updated]} updated, " \
        "#{stats[:unchanged]} unchanged, #{stats[:invalid]} invalid, #{stats[:removed]} removed"
      )

      { success: true }.merge(stats)
    rescue RateLimitable::RateLimitExceeded => e
      failure("rate limited", retry_after: e.retry_after)
    rescue ServiceError => e
      failure(e.message)
    end

    private

    def failure(message, extra = {})
      log_info("IOK sync failed: #{message}")
      { success: false, error: message }.merge(extra)
    end

    def download_archive
      response = connection(base_url: ARCHIVE_URL, timeout: ARCHIVE_TIMEOUT).get do |request|
        request.headers["Accept"] = "application/gzip"
      end

      body = response.body.to_s
      raise ServiceError, "archive download was empty" if body.empty?

      body
    rescue Faraday::Error => e
      raise ServiceError, "could not download #{ARCHIVE_URL}: #{e.message}"
    end

    # @return [Array<Hash>] one parsed indicator per entry, invalid YAML skipped
    def parse_archive(archive)
      documents = []

      Gem::Package::TarReader.new(Zlib::GzipReader.new(StringIO.new(archive))) do |tar|
        tar.each do |entry|
          next unless entry.file?

          match = INDICATOR_ENTRY.match(entry.full_name)
          next unless match

          contents = entry.read.to_s
          document = parse_document(match[:slug], contents)
          documents << document if document
        end
      end

      documents
    rescue Zlib::Error, Gem::Package::TarInvalidError => e
      raise ServiceError, "could not read archive: #{e.message}"
    end

    def parse_document(slug, contents)
      parsed = YAML.safe_load(contents, permitted_classes: [ Date, Time ], aliases: false)
      unless parsed.is_a?(Hash)
        log_info("Skipping #{slug}: not a YAML mapping")
        return nil
      end

      {
        slug: slug.downcase,
        title: parsed["title"].to_s.presence || slug,
        description: parsed["description"].to_s.presence,
        level: parsed["level"].to_s.presence,
        reference_urls: Array(parsed["references"]).map(&:to_s),
        tags: Array(parsed["tags"]).map(&:to_s),
        # The column is NOT NULL, so a rule with no detection block at all has
        # to reach validation as an empty mapping rather than as nil.
        detection: parsed["detection"].is_a?(Hash) ? parsed["detection"] : {},
        source_url: "#{REPOSITORY_URL}/blob/main/indicators/#{slug}.yml",
        content_digest: Digest::SHA256.hexdigest(contents),
        synced_at: Time.current
      }
    rescue Psych::Exception => e
      log_info("Skipping #{slug}: #{e.message}")
      nil
    end

    def persist(documents)
      stats = { created: 0, updated: 0, unchanged: 0, invalid: 0, removed: 0 }

      # Includes discarded rows on purpose: an indicator withdrawn upstream and
      # later restored has to come back as the same record, or the partial
      # unique index leaves two rows for one slug.
      existing = Iok::Indicator
                   .with_discarded
                   .where(slug: documents.map { |doc| doc[:slug] })
                   .index_by(&:slug)

      documents.each do |document|
        outcome = upsert(existing[document[:slug]], document)
        stats[outcome] += 1
      end

      stats[:removed] = retire_missing(documents.map { |doc| doc[:slug] })
      stats
    end

    # @return [Symbol] :created, :updated, :unchanged or :invalid
    def upsert(indicator, document)
      if indicator.nil?
        return Iok::Indicator.create(document).persisted? ? :created : record_invalid(document)
      end

      if indicator.discarded?
        indicator.undiscard
        return indicator.update(document) ? :created : record_invalid(document)
      end

      # The digest covers the whole upstream file, so an unchanged digest means
      # nothing about this indicator needs writing.
      if indicator.content_digest == document[:content_digest]
        indicator.update_column(:synced_at, document[:synced_at])
        return :unchanged
      end

      indicator.update(document) ? :updated : record_invalid(document)
    end

    def record_invalid(document)
      log_info("Skipping #{document[:slug]}: detection block did not compile")
      :invalid
    end

    # Indicators withdrawn upstream are discarded rather than deleted, so a bad
    # sync can be undone and the history stays auditable.
    def retire_missing(slugs)
      stale = Iok::Indicator.where.not(slug: slugs)
      count = stale.count
      stale.find_each(&:discard)
      count
    end
  end
end
