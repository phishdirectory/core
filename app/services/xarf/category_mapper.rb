# frozen_string_literal: true

module Xarf
  # Maps between phish.directory classifications and the X-ARF schema 3
  # taxonomy published at https://github.com/abusix/xarf.
  #
  # Schema 3 splits a report into a ReportClass and a ReportType. There are
  # three classes and one type per schema file:
  #
  #   Content        Phishing, Malware, Copyright, Trademark, ChildAbuse, Botnet
  #   Activity       Spam, DOS, PortScan, LoginAttack, Exploit, WebCrawler,
  #                  Harassment, PotentiallyCompromisedAccount, Malware (RPZ)
  #   Vulnerability  OpenService
  #
  # phish.directory Classifications:
  #   - phishing: Confirmed phishing sites
  #   - suspicious: Potentially malicious but not confirmed
  #   - clean: Known safe
  #   - unknown: Not yet classified
  #   - protected: Protected domains (whitelisted)
  #
  class CategoryMapper
    REPORT_CLASSES = %w[Content Activity Vulnerability].freeze

    # Types by class, taken from the schema 3 files. Malware appears twice
    # because the RPZ schema reports it as Activity with an RPZ-Rewrite
    # subtype, while the malware schema reports it as Content.
    REPORT_TYPES = {
      "Content" => %w[Phishing Malware Copyright Trademark ChildAbuse Botnet].freeze,
      "Activity" => %w[
        Spam
        DOS
        PortScan
        LoginAttack
        Exploit
        PotentiallyCompromisedAccount
        WebCrawler
        Harassment
        Malware
      ].freeze,
      "Vulnerability" => %w[OpenService].freeze
    }.freeze

    # Mapping from phish.directory classification to X-ARF class/type.
    #
    # Schema 3 has no type for an unconfirmed site, so "suspicious" is reported
    # as Phishing too. ReporterSeverity and the notes carry the confidence, so
    # the receiving desk still sees that the finding is not confirmed.
    CLASSIFICATION_TO_XARF = {
      "phishing" => { report_class: "Content", report_type: "Phishing" },
      "suspicious" => { report_class: "Content", report_type: "Phishing" },
      "clean" => nil, # Clean domains don't need X-ARF reports
      "unknown" => nil, # Unknown domains don't have enough info for X-ARF
      "protected" => nil # Protected domains shouldn't be reported
    }.freeze

    # Mapping from X-ARF type to phish.directory classification.
    # nil means the type is real but outside what this directory classifies.
    XARF_TYPE_TO_CLASSIFICATION = {
      "Phishing" => "phishing",
      "Malware" => "phishing",
      "Botnet" => "phishing",
      "Exploit" => "phishing",
      "Trademark" => "suspicious",
      "Spam" => "suspicious",
      "LoginAttack" => "suspicious",
      "PortScan" => "suspicious",
      "DOS" => "suspicious",
      "WebCrawler" => "suspicious",
      "PotentiallyCompromisedAccount" => "suspicious",
      "OpenService" => "suspicious",
      "Copyright" => nil,
      "ChildAbuse" => nil,
      "Harassment" => nil
    }.freeze

    # Confidence score for an incoming type to classification mapping.
    # Higher values = more confidence the mapping is accurate.
    XARF_TYPE_CONFIDENCE = {
      "Phishing" => 1.0,
      "Malware" => 0.95,
      "Botnet" => 0.85,
      "Exploit" => 0.8,
      "Trademark" => 0.7,
      "Spam" => 0.5,
      "LoginAttack" => 0.5,
      "PortScan" => 0.5,
      "DOS" => 0.5,
      "WebCrawler" => 0.4,
      "PotentiallyCompromisedAccount" => 0.6,
      "OpenService" => 0.5
    }.freeze

    DEFAULT_CONFIDENCE = 0.5

    # Severity thresholds. ReporterSeverity is a closed low/medium/high enum.
    HIGH_CONFIDENCE = 0.9
    MEDIUM_CONFIDENCE = 0.7

    class << self
      # Convert phish.directory classification to X-ARF class/type
      #
      # @param classification [String] phish.directory classification
      # @param report_type [String, nil] optional override for a more specific type
      # @return [Hash, nil] { report_class:, report_type: } or nil if not mappable
      def to_xarf(classification, report_type: nil)
        mapping = CLASSIFICATION_TO_XARF[classification.to_s]
        return nil if mapping.nil?

        if report_type && valid_report_type?(report_type)
          { report_class: classes_for_type(report_type).first, report_type: report_type.to_s }
        else
          mapping
        end
      end

      # Convert X-ARF class/type to phish.directory classification
      #
      # @param report_class [String] X-ARF ReportClass
      # @param report_type [String] X-ARF ReportType
      # @return [String, nil] phish.directory classification or nil
      def from_xarf(report_class, report_type)
        return nil unless valid_report_class?(report_class)
        return nil unless valid_report_type?(report_type)

        XARF_TYPE_TO_CLASSIFICATION[report_type.to_s]
      end

      # Get confidence score for an X-ARF type to classification mapping
      #
      # @param report_type [String] X-ARF ReportType
      # @return [Float] confidence score (0.0 - 1.0)
      def confidence_for_type(report_type)
        XARF_TYPE_CONFIDENCE.fetch(report_type.to_s, DEFAULT_CONFIDENCE)
      end

      # Check if a classification is reportable via X-ARF
      #
      # @param classification [String] phish.directory classification
      # @return [Boolean]
      def reportable?(classification)
        CLASSIFICATION_TO_XARF[classification.to_s].present?
      end

      # Get every ReportClass a type may appear under
      #
      # @param report_type [String] X-ARF ReportType
      # @return [Array<String>] classes, most common first
      def classes_for_type(report_type)
        REPORT_TYPES.select { |_klass, types| types.include?(report_type.to_s) }.keys
      end

      # Validate a ReportClass
      #
      # @param report_class [String]
      # @return [Boolean]
      def valid_report_class?(report_class)
        REPORT_CLASSES.include?(report_class.to_s)
      end

      # Validate a ReportType
      #
      # @param report_type [String]
      # @return [Boolean]
      def valid_report_type?(report_type)
        REPORT_TYPES.values.flatten.include?(report_type.to_s)
      end

      # Check that a type is allowed under a class
      #
      # @param report_class [String]
      # @param report_type [String]
      # @return [Boolean]
      def type_in_class?(report_class, report_type)
        REPORT_TYPES.fetch(report_class.to_s, []).include?(report_type.to_s)
      end

      # Get all types for a class
      #
      # @param report_class [String]
      # @return [Array<String>] list of types
      def types_for_class(report_class)
        REPORT_TYPES.fetch(report_class.to_s, [])
      end

      # Map a verdict onto an X-ARF class/type with full context
      #
      # @param verdict [Verdict] verdict record
      # @return [Hash] { report_class:, report_type:, confidence:, reportable: }
      def map_verdict(verdict)
        return { reportable: false } if verdict.nil?

        mapping = to_xarf(verdict.classification)
        return { reportable: false } unless mapping

        mapping.merge(
          confidence: verdict.confidence_score || DEFAULT_CONFIDENCE,
          reportable: true
        )
      end

      # Severity for a confidence score, as the ReporterSeverity enum
      #
      # @param confidence [Float, nil]
      # @return [String] "low", "medium" or "high"
      def severity_for_confidence(confidence)
        case confidence.to_f
        when HIGH_CONFIDENCE.. then "high"
        when MEDIUM_CONFIDENCE...HIGH_CONFIDENCE then "medium"
        else "low"
        end
      end

      # Describe an X-ARF type
      #
      # @param report_type [String] X-ARF ReportType
      # @return [Hash, nil] { report_class:, report_type:, description: }
      def type_info(report_type)
        classes = classes_for_type(report_type)
        return nil if classes.empty?

        {
          report_class: classes.first,
          report_type: report_type.to_s,
          description: type_description(report_type)
        }
      end

      private

      def type_description(report_type)
        {
          "Phishing" => "Fraudulent attempt to obtain sensitive information",
          "Malware" => "Malicious software distribution",
          "Copyright" => "Copyright infringing content",
          "Trademark" => "Unauthorized use of brand identity",
          "ChildAbuse" => "Child sexual abuse material",
          "Botnet" => "Botnet command and control",
          "Spam" => "Unsolicited bulk messaging",
          "DOS" => "Denial of service attack",
          "PortScan" => "Network port scanning activity",
          "LoginAttack" => "Brute force or credential stuffing attack",
          "Exploit" => "Attempt to exploit a vulnerability",
          "PotentiallyCompromisedAccount" => "Account showing signs of compromise",
          "WebCrawler" => "Unwanted automated crawling",
          "Harassment" => "Harassment of an individual",
          "OpenService" => "Service exposed that should not be reachable"
        }.fetch(report_type.to_s, "Unknown abuse type")
      end
    end
  end
end
