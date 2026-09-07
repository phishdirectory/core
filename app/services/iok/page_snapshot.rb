# frozen_string_literal: true

require "faraday"
require "nokogiri"

module Iok
  # The page content an IOK rule is evaluated against.
  #
  # Upstream, phish.report builds this from a urlscan.io scan, which has a real
  # browser behind it. We fetch the page over plain HTTP instead, which is the
  # same trade-off the reference implementation makes in its `nethttp` path:
  #
  #   * `dom` is the served HTML, not the HTML after JavaScript has run.
  #   * `requests` covers the subresources named in the markup, not the ones a
  #     script asks for later.
  #
  # We do go one step further than the reference implementation and fetch a
  # bounded number of the linked scripts and stylesheets, because a quarter of
  # the corpus matches on `js` and those rules cannot fire on inline script
  # alone.
  #
  # Every URL, including each redirect hop and each subresource, goes through
  # WebhookAddressPolicy first. The check submits an attacker-chosen URL to our
  # own workers, so without that a caller could use this to reach the metadata
  # endpoint or anything else inside our network.
  class PageSnapshot
    class FetchError < StandardError; end
    class BlockedAddress < FetchError; end

    DEFAULT_TIMEOUT = 15
    DEFAULT_OPEN_TIMEOUT = 5
    MAX_REDIRECTS = 3
    MAX_BODY_BYTES = 2_000_000
    MAX_ASSETS = 8
    MAX_ASSET_BYTES = 500_000

    # Attributes that cause a browser to issue a request. Mirrors
    # extractRequests in phish-report/IOK.
    REQUEST_SOURCES = {
      "link" => "href",
      "img" => "src",
      "script" => "src"
    }.freeze

    attr_reader :url, :fields

    def initialize(url:, fields:)
      @url = url
      @fields = fields
    end

    class << self
      # @param url [String] the page to snapshot
      # @param fetch_assets [Boolean] also download linked scripts and
      #   stylesheets, up to MAX_ASSETS of them
      # @return [Iok::PageSnapshot]
      # @raise [FetchError] if the page cannot be retrieved
      def capture(url, logger: Rails.logger, fetch_assets: true)
        new_from_response(url, logger: logger, fetch_assets: fetch_assets)
      end

      private

      def new_from_response(url, logger:, fetch_assets:)
        final_url, response = Fetcher.new(logger: logger).get_page(url)
        Builder.new(
          url: final_url,
          response: response,
          logger: logger,
          fetch_assets: fetch_assets
        ).build
      end
    end

    # @return [Array<String>] every value the page has for this field
    def values_for(field)
      fields.fetch(field.to_s, [])
    end

    # Small summary for logging and verdict details. Deliberately excludes the
    # page body, which can be megabytes.
    def summary
      {
        url: url,
        title: values_for("title").first,
        assets: values_for("js").length + values_for("css").length,
        requests: values_for("requests").length
      }
    end

    # Issues the HTTP requests, following redirects by hand so that the address
    # policy runs on every hop rather than only the first one.
    class Fetcher
      def initialize(logger:)
        @logger = logger
      end

      # @return [Array(String, Faraday::Response)] the final URL and response
      def get_page(url)
        current = normalize(url)
        seen = []

        MAX_REDIRECTS.succ.times do
          guard!(current)
          response = request(current)

          location = redirect_target(response, current)
          return [ current, response ] if location.nil?

          raise FetchError, "redirect loop at #{current}" if seen.include?(location)

          seen << current
          current = location
        end

        raise FetchError, "too many redirects starting at #{url}"
      end

      # Subresources are best effort: a script we cannot fetch just means the
      # rules that look at it do not fire.
      def get_asset(url)
        guard!(url)
        body = request(url).body
        truncate(body, MAX_ASSET_BYTES)
      rescue FetchError, Faraday::Error, URI::Error => e
        @logger.debug("[iok] skipping asset #{url}: #{e.message}")
        nil
      end

      private

      def normalize(url)
        uri = URI.parse(url.to_s.strip)
        uri = URI.parse("https://#{url.to_s.strip}") unless uri.scheme

        unless uri.is_a?(URI::HTTP)
          raise FetchError, "unsupported scheme in #{url.inspect}"
        end

        uri.to_s
      rescue URI::InvalidURIError
        raise FetchError, "could not parse #{url.inspect}"
      end

      def guard!(url)
        return unless WebhookAddressPolicy.internal?(url)

        raise BlockedAddress, "refusing to fetch internal address #{url}"
      end

      def request(url)
        connection.get(url)
      rescue Faraday::Error => e
        raise FetchError, "could not fetch #{url}: #{e.message}"
      end

      def redirect_target(response, current)
        return nil unless (300..399).cover?(response.status)

        location = response.headers["location"]
        return nil if location.blank?

        normalize(URI.join(current, location).to_s)
      rescue URI::Error
        nil
      end

      def truncate(body, limit)
        text = body.to_s
        text = text.byteslice(0, limit).to_s if text.bytesize > limit
        text.dup.force_encoding(Encoding::UTF_8).scrub("")
      end

      # A separate connection from Phish::BaseService#connection: that one asks
      # for JSON and parses the response, and here we want the bytes the site
      # served. Redirects are handled above, not by middleware, and errors are
      # not raised because a 404 page can itself match a rule.
      def connection
        @connection ||= Faraday.new do |conn|
          conn.options.timeout = DEFAULT_TIMEOUT
          conn.options.open_timeout = DEFAULT_OPEN_TIMEOUT
          conn.headers["User-Agent"] = user_agent
          conn.headers["Accept"] = "text/html,application/xhtml+xml,*/*"
          conn.ssl.verify = true
          conn.ssl.cert_store = Phish::BaseService.certificate_store
          conn.adapter Faraday.default_adapter
        end
      end

      def user_agent
        "@phishdirectory/core/#{ENV.fetch('RELEASE_VERSION', '1.0.0')} (https://phish.directory)"
      end
    end

    # Turns a fetched response into the field map that Iok::Rule evaluates.
    class Builder
      def initialize(url:, response:, logger:, fetch_assets:)
        @url = url
        @response = response
        @logger = logger
        @fetch_assets = fetch_assets
      end

      def build
        html = normalize_body(@response.body)
        document = Nokogiri::HTML5(html)

        fields = {
          "hostname" => [ URI.parse(@url).host ].compact,
          "html" => [ html ],
          "dom" => [ html ],
          "title" => titles(document),
          "headers" => headers,
          "cookies" => cookies,
          "requests" => requests(document),
          "js" => inline(document, "script"),
          "css" => inline(document, "style")
        }

        fetch_linked_assets(document, fields) if @fetch_assets

        PageSnapshot.new(url: @url, fields: fields)
      end

      private

      # The body can be any encoding, or none at all. Rules are UTF-8, so
      # anything that will not compare cleanly is scrubbed here rather than
      # rescued on every single comparison.
      def normalize_body(body)
        text = body.to_s
        text = text.byteslice(0, MAX_BODY_BYTES).to_s if text.bytesize > MAX_BODY_BYTES
        text.dup.force_encoding(Encoding::UTF_8).scrub("")
      end

      # `<title>` inside an `<svg>` is not the page title, which is why the
      # upstream extractor checks the namespace. Nokogiri gives us the same
      # distinction through the CSS selector.
      def titles(document)
        document.css("title").filter_map do |node|
          next if node.ancestors("svg").any?

          node.text.strip.presence
        end
      end

      def headers
        @response.headers.flat_map do |name, value|
          Array(value).map { |entry| "#{canonical(name)}: #{entry}" }
        end
      end

      def canonical(name)
        name.to_s.split("-").map(&:capitalize).join("-")
      end

      # Adapters differ in how they hand back repeated Set-Cookie headers: some
      # keep them separate, Net::HTTP folds them into one comma-joined string.
      # The lookahead splits on a comma that starts a new `name=` pair, which
      # leaves the comma inside an `Expires=Wed, 09 Jun 2021` attribute alone.
      COOKIE_SEPARATOR = /\n|,\s*(?=[^;,=\s]+=)/

      def cookies
        Array(@response.headers["set-cookie"])
          .flat_map { |header| header.to_s.split(COOKIE_SEPARATOR) }
          .filter_map { |header| header.split(";").first.to_s.strip.presence }
      end

      # The page itself counts as a request, matching the upstream extractor.
      def requests(document)
        found = [ @url ]

        REQUEST_SOURCES.each do |tag, attribute|
          document.css(tag).each do |node|
            value = node[attribute]
            next if value.blank?

            found << absolute(value)
          end
        end

        found.compact.uniq
      end

      def absolute(value)
        URI.join(@url, value).to_s
      rescue URI::Error
        nil
      end

      def inline(document, tag)
        document.css(tag).filter_map do |node|
          next if node["src"].present?

          node.content.presence
        end
      end

      # Bounded on purpose: this runs inside a domain check that the aggregator
      # gives 35 seconds in total, so a page with 200 scripts must not turn one
      # check into 200 requests.
      def fetch_linked_assets(document, fields)
        fetcher = Fetcher.new(logger: @logger)

        linked_assets(document).first(MAX_ASSETS).each do |field, url|
          body = fetcher.get_asset(url)
          fields[field] << body if body.present?
        end
      end

      def linked_assets(document)
        scripts = document.css("script[src]").filter_map do |node|
          url = absolute(node["src"])
          [ "js", url ] if url
        end

        styles = document.css('link[rel~="stylesheet"][href]').filter_map do |node|
          url = absolute(node["href"])
          [ "css", url ] if url
        end

        (scripts + styles).uniq
      end
    end
  end
end
