# frozen_string_literal: true

module Xarf
  # Maps between phish.directory classifications and XARF v4 categories/types
  #
  # XARF v4 Categories (7):
  #   - connection: Network-level attacks (login_attack, port_scan, ddos, etc.)
  #   - content: Malicious/harmful content (phishing, malware, fraud, etc.)
  #   - copyright: IP infringement (copyright, p2p, cyberlocker, etc.)
  #   - infrastructure: Compromised systems (botnet, compromised_server)
  #   - messaging: Spam and bulk messaging (spam, bulk_messaging)
  #   - reputation: Threat intel and blocklists (blocklist, threat_intelligence)
  #   - vulnerability: Security issues (cve, open, misconfiguration)
  #
  # phish.directory Classifications:
  #   - phishing: Confirmed phishing sites
  #   - suspicious: Potentially malicious but not confirmed
  #   - clean: Known safe
  #   - unknown: Not yet classified
  #   - protected: Protected domains (whitelisted)
  #
  class CategoryMapper
    # XARF v4 categories
    XARF_CATEGORIES = %w[
      connection
      content
      copyright
      infrastructure
      messaging
      reputation
      vulnerability
    ].freeze

    # XARF v4 types organized by category
    XARF_TYPES = {
      connection: %w[
        login_attack
        port_scan
        ddos
        infected_host
        reconnaissance
        scraping
        sql_injection
        vuln_scanning
      ].freeze,
      content: %w[
        phishing
        malware
        csam
        csem
        exposed_data
        brand_infringement
        fraud
        remote_compromise
        suspicious_registration
      ].freeze,
      copyright: %w[
        copyright
        p2p
        cyberlocker
        ugc_platform
        link_site
        usenet
      ].freeze,
      infrastructure: %w[
        botnet
        compromised_server
      ].freeze,
      messaging: %w[
        spam
        bulk_messaging
      ].freeze,
      reputation: %w[
        blocklist
        threat_intelligence
      ].freeze,
      vulnerability: %w[
        cve
        open
        misconfiguration
      ].freeze
    }.freeze

    # Mapping from phish.directory classification to XARF category/type
    CLASSIFICATION_TO_XARF = {
      "phishing" => { category: "content", type: "phishing" },
      "suspicious" => { category: "content", type: "suspicious_registration" },
      "clean" => nil, # Clean domains don't need XARF reports
      "unknown" => nil, # Unknown domains don't have enough info for XARF
      "protected" => nil # Protected domains shouldn't be reported
    }.freeze

    # Mapping from XARF type to phish.directory classification
    XARF_TYPE_TO_CLASSIFICATION = {
      # Content types
      "phishing" => "phishing",
      "malware" => "phishing",
      "fraud" => "phishing",
      "brand_infringement" => "suspicious",
      "suspicious_registration" => "suspicious",
      "exposed_data" => "suspicious",
      "remote_compromise" => "phishing",
      "csam" => "phishing",
      "csem" => "phishing",

      # Connection types (usually infrastructure-level, map to suspicious)
      "login_attack" => "suspicious",
      "port_scan" => "suspicious",
      "ddos" => "suspicious",
      "infected_host" => "phishing",
      "reconnaissance" => "suspicious",
      "scraping" => "suspicious",
      "sql_injection" => "phishing",
      "vuln_scanning" => "suspicious",

      # Infrastructure types
      "botnet" => "phishing",
      "compromised_server" => "phishing",

      # Messaging types
      "spam" => "suspicious",
      "bulk_messaging" => "suspicious",

      # Reputation types (informational)
      "blocklist" => "suspicious",
      "threat_intelligence" => "suspicious",

      # Copyright types (not typically phishing)
      "copyright" => nil,
      "p2p" => nil,
      "cyberlocker" => nil,
      "ugc_platform" => nil,
      "link_site" => nil,
      "usenet" => nil,

      # Vulnerability types
      "cve" => "suspicious",
      "open" => "suspicious",
      "misconfiguration" => "suspicious"
    }.freeze

    # Confidence score adjustments based on XARF type
    # Higher values = more confidence the mapping is accurate
    XARF_TYPE_CONFIDENCE = {
      "phishing" => 1.0,
      "malware" => 0.95,
      "fraud" => 0.9,
      "infected_host" => 0.85,
      "botnet" => 0.85,
      "compromised_server" => 0.8,
      "brand_infringement" => 0.7,
      "suspicious_registration" => 0.6,
      "spam" => 0.5,
      "blocklist" => 0.6,
      "threat_intelligence" => 0.7
    }.freeze

    DEFAULT_CONFIDENCE = 0.5

    class << self
      # Convert phish.directory classification to XARF category/type
      #
      # @param classification [String] phish.directory classification
      # @param subtype [String, nil] optional subtype for more specific mapping
      # @return [Hash, nil] { category:, type: } or nil if not mappable
      def to_xarf(classification, subtype: nil)
        mapping = CLASSIFICATION_TO_XARF[classification.to_s]
        return nil if mapping.nil?

        # Allow subtype override for more specific mappings
        if subtype && valid_xarf_type?(subtype)
          { category: category_for_type(subtype), type: subtype }
        else
          mapping
        end
      end

      # Convert XARF category/type to phish.directory classification
      #
      # @param category [String] XARF category
      # @param type [String] XARF type
      # @return [String, nil] phish.directory classification or nil
      def from_xarf(category, type)
        return nil unless valid_xarf_category?(category)
        return nil unless valid_xarf_type?(type)

        XARF_TYPE_TO_CLASSIFICATION[type.to_s]
      end

      # Get confidence score for XARF type to classification mapping
      #
      # @param type [String] XARF type
      # @return [Float] confidence score (0.0 - 1.0)
      def confidence_for_type(type)
        XARF_TYPE_CONFIDENCE.fetch(type.to_s, DEFAULT_CONFIDENCE)
      end

      # Check if a classification is reportable via XARF
      #
      # @param classification [String] phish.directory classification
      # @return [Boolean]
      def reportable?(classification)
        CLASSIFICATION_TO_XARF[classification.to_s].present?
      end

      # Get the XARF category for a given type
      #
      # @param type [String] XARF type
      # @return [String, nil] XARF category or nil
      def category_for_type(type)
        XARF_TYPES.each do |category, types|
          return category.to_s if types.include?(type.to_s)
        end
        nil
      end

      # Validate XARF category
      #
      # @param category [String] XARF category
      # @return [Boolean]
      def valid_xarf_category?(category)
        XARF_CATEGORIES.include?(category.to_s)
      end

      # Validate XARF type
      #
      # @param type [String] XARF type
      # @return [Boolean]
      def valid_xarf_type?(type)
        XARF_TYPES.values.flatten.include?(type.to_s)
      end

      # Get all XARF types for a category
      #
      # @param category [String, Symbol] XARF category
      # @return [Array<String>] list of types
      def types_for_category(category)
        XARF_TYPES[category.to_sym] || []
      end

      # Map verdict object to XARF category/type with full context
      #
      # @param verdict [Verdict] verdict record
      # @return [Hash] { category:, type:, confidence:, reportable: }
      def map_verdict(verdict)
        return { reportable: false } if verdict.nil?

        xarf_mapping = to_xarf(verdict.classification)

        if xarf_mapping
          {
            category: xarf_mapping[:category],
            type: xarf_mapping[:type],
            confidence: verdict.confidence_score || DEFAULT_CONFIDENCE,
            reportable: true
          }
        else
          { reportable: false }
        end
      end

      # Get descriptive info about a XARF type
      #
      # @param type [String] XARF type
      # @return [Hash] { category:, description:, severity: }
      def type_info(type)
        category = category_for_type(type)
        return nil unless category

        {
          category: category,
          type: type,
          description: type_description(type),
          severity: type_severity(type)
        }
      end

      private

      def type_description(type)
        {
          # Content types
          "phishing" => "Fraudulent attempt to obtain sensitive information",
          "malware" => "Malicious software distribution",
          "fraud" => "Deceptive practices for financial gain",
          "brand_infringement" => "Unauthorized use of brand identity",
          "suspicious_registration" => "Domain registered with suspicious patterns",
          "exposed_data" => "Sensitive data exposure",
          "remote_compromise" => "Remote system compromise",
          "csam" => "Child sexual abuse material",
          "csem" => "Child sexual exploitation material",

          # Connection types
          "login_attack" => "Brute force or credential stuffing attack",
          "port_scan" => "Network port scanning activity",
          "ddos" => "Distributed denial of service attack",
          "infected_host" => "Compromised host exhibiting malicious behavior",
          "reconnaissance" => "Information gathering for potential attack",
          "scraping" => "Unauthorized data scraping",
          "sql_injection" => "SQL injection attack attempt",
          "vuln_scanning" => "Vulnerability scanning activity",

          # Infrastructure types
          "botnet" => "Part of a botnet command and control",
          "compromised_server" => "Server showing signs of compromise",

          # Messaging types
          "spam" => "Unsolicited bulk messaging",
          "bulk_messaging" => "High-volume messaging campaign",

          # Reputation types
          "blocklist" => "Listed on security blocklist",
          "threat_intelligence" => "Identified in threat intelligence feed"
        }.fetch(type.to_s, "Unknown abuse type")
      end

      def type_severity(type)
        case type.to_s
        when "phishing", "malware", "csam", "csem", "remote_compromise", "botnet"
          "critical"
        when "fraud", "infected_host", "compromised_server", "sql_injection"
          "high"
        when "brand_infringement", "login_attack", "ddos", "spam"
          "medium"
        else
          "low"
        end
      end
    end
  end
end
