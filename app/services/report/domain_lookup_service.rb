# frozen_string_literal: true

module Report
  # Service for looking up domain registration and hosting information
  # Uses RDAP (preferred) with WHOIS fallback
  class DomainLookupService < BaseService
    CACHE_TTL = 24.hours

    # RDAP bootstrap servers by TLD
    # See: https://data.iana.org/rdap/dns.json
    RDAP_SERVERS = {
      "com" => "https://rdap.verisign.com/com/v1",
      "net" => "https://rdap.verisign.com/net/v1",
      "org" => "https://rdap.publicinterestregistry.org/rdap",
      "io" => "https://rdap.nic.io",
      "co" => "https://rdap.nic.co",
      "dev" => "https://rdap.nic.google",
      "app" => "https://rdap.nic.google",
      "page" => "https://rdap.nic.google",
      "xyz" => "https://rdap.centralnic.com/xyz",
      "info" => "https://rdap.afilias.net/rdap/info",
      "me" => "https://rdap.nic.me",
      "cc" => "https://rdap.nic.cc",
      "ru" => "https://rdap.tcinet.ru",
      "de" => "https://rdap.denic.de"
      # Add more as needed
    }.freeze

    def lookup(domain)
      domain = normalize_domain(domain)

      # Check cache first
      cached = Report::DomainLookup.for_domain(domain)
      return cached if cached&.fresh?

      # Perform lookup
      result = lookup_rdap(domain) || lookup_whois(domain)

      if result
        save_lookup(domain, result)
      else
        log_info("No lookup data found for #{domain}")
        nil
      end
    end

    private

    def normalize_domain(domain)
      domain.to_s.downcase.strip.sub(/^www\./, "")
    end

    def lookup_rdap(domain)
      tld = domain.split(".").last&.downcase
      rdap_url = RDAP_SERVERS[tld]

      unless rdap_url
        log_debug("No RDAP server configured for TLD: #{tld}")
        return nil
      end

      log_info("Looking up #{domain} via RDAP")

      conn = connection(base_url: rdap_url, timeout: 15)
      response = get(conn, "domain/#{domain}")

      parse_rdap_response(response)
    rescue ServiceError => e
      log_error("RDAP lookup failed", e)
      nil
    end

    def lookup_whois(domain)
      log_info("Looking up #{domain} via WHOIS")

      # Use the whois gem for lookup
      record = Whois.whois(domain)
      return nil if record.nil? || record.content.blank?

      # Parse with whois-parser
      parser = record.parser
      return nil unless parser.registered?

      {
        lookup_source: "whois",
        registrar_name: extract_whois_registrar(parser),
        registrar_iana_id: parser.registrar&.id,
        registrar_abuse_email: extract_whois_abuse_email(parser, record),
        registrar_abuse_phone: parser.registrar&.respond_to?(:phone) ? parser.registrar.phone : nil,
        domain_created_at: parser.created_on,
        domain_expires_at: parser.expires_on,
        nameservers: parser.nameservers&.map(&:name) || [],
        raw_whois: record.content.truncate(50_000) # Limit raw storage
      }
    rescue Whois::Error, Whois::ConnectionError, Timeout::Error => e
      log_error("WHOIS lookup failed", e)
      nil
    rescue Whois::ParserNotFound
      log_debug("No WHOIS parser available for #{domain}")
      nil
    end

    def extract_whois_registrar(parser)
      return parser.registrar.name if parser.registrar&.respond_to?(:name) && parser.registrar.name.present?
      return parser.registrar.organization if parser.registrar&.respond_to?(:organization)

      nil
    end

    def extract_whois_abuse_email(parser, record)
      # Try structured abuse contact first
      if parser.respond_to?(:technical_contacts) && parser.technical_contacts.any?
        email = parser.technical_contacts.first&.email
        return email if email.present? && email.include?("abuse")
      end

      if parser.respond_to?(:admin_contacts) && parser.admin_contacts.any?
        email = parser.admin_contacts.first&.email
        return email if email.present?
      end

      # Fallback: scan raw WHOIS for abuse email
      content = record.content.to_s
      if (match = content.match(/abuse.*?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i))
        return match[1].downcase
      end

      # Try registrar abuse email
      if (match = content.match(/Registrar Abuse.*?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i))
        return match[1].downcase
      end

      nil
    end

    def parse_rdap_response(response)
      return nil unless response.is_a?(Hash)

      {
        lookup_source: "rdap",
        registrar_name: extract_registrar_name(response),
        registrar_iana_id: response.dig("entities", 0, "publicIds")&.find { |p| p["type"] == "IANA Registrar ID" }&.dig("identifier"),
        registrar_abuse_email: extract_abuse_email(response),
        registrar_abuse_phone: extract_abuse_phone(response),
        domain_created_at: parse_event_date(response, "registration"),
        domain_expires_at: parse_event_date(response, "expiration"),
        nameservers: extract_nameservers(response),
        raw_rdap: response
      }
    end

    def extract_registrar_name(response)
      # Look for registrar entity
      registrar = response["entities"]&.find { |e| e["roles"]&.include?("registrar") }
      return nil unless registrar

      # Try vcard fn (formatted name)
      vcard = registrar["vcardArray"]
      if vcard.is_a?(Array) && vcard[1].is_a?(Array)
        fn = vcard[1].find { |v| v.is_a?(Array) && v[0] == "fn" }
        return fn[3] if fn
      end

      # Fallback to handle
      registrar["handle"]
    end

    def extract_abuse_email(response)
      # Look for abuse contact in entities
      response["entities"]&.each do |entity|
        next unless entity["roles"]&.include?("abuse")

        vcard = entity["vcardArray"]
        if vcard.is_a?(Array) && vcard[1].is_a?(Array)
          email = vcard[1].find { |v| v.is_a?(Array) && v[0] == "email" }
          return email[3] if email
        end
      end

      nil
    end

    def extract_abuse_phone(response)
      response["entities"]&.each do |entity|
        next unless entity["roles"]&.include?("abuse")

        vcard = entity["vcardArray"]
        if vcard.is_a?(Array) && vcard[1].is_a?(Array)
          tel = vcard[1].find { |v| v.is_a?(Array) && v[0] == "tel" }
          return tel[3] if tel
        end
      end

      nil
    end

    def extract_nameservers(response)
      response["nameservers"]&.map { |ns| ns["ldhName"] || ns["objectClassName"] }&.compact || []
    end

    def parse_event_date(response, event_action)
      event = response["events"]&.find { |e| e["eventAction"] == event_action }
      return nil unless event&.dig("eventDate")

      Time.parse(event["eventDate"])
    rescue ArgumentError
      nil
    end

    def save_lookup(domain, result)
      lookup = Report::DomainLookup.find_or_initialize_by(domain: domain)

      attrs = {
        registrar_name: result[:registrar_name],
        registrar_iana_id: result[:registrar_iana_id],
        registrar_abuse_email: result[:registrar_abuse_email],
        registrar_abuse_phone: result[:registrar_abuse_phone],
        domain_created_at: result[:domain_created_at],
        domain_expires_at: result[:domain_expires_at],
        nameservers: result[:nameservers],
        lookup_source: result[:lookup_source],
        looked_up_at: Time.current,
        expires_at: CACHE_TTL.from_now
      }

      # Store raw data in appropriate column based on source
      if result[:lookup_source] == "rdap"
        attrs[:raw_rdap] = result[:raw_rdap]
      elsif result[:lookup_source] == "whois"
        attrs[:raw_whois] = result[:raw_whois]
      end

      lookup.assign_attributes(attrs)

      lookup.save!

      # Try to match to known abuse contacts
      lookup.match_contacts!

      log_info("Saved lookup for #{domain} (registrar: #{lookup.registrar_name})")

      lookup
    end
  end
end
