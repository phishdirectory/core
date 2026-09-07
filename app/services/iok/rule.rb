# frozen_string_literal: true

module Iok
  # A compiled IOK detection block.
  #
  # IOK rules are Sigma rules evaluated against a page snapshot, so the
  # semantics here follow bradleyjkemp/sigma-go, which is what phish.report
  # runs upstream:
  #
  #   * A selection is a map of field matchers. Every field matcher in the
  #     selection has to match (AND).
  #   * A selection given as a list of maps matches when any one map matches
  #     (OR).
  #   * A field matcher with a list of values matches when any value matches.
  #     With the `all` modifier, every value has to match.
  #   * Each value is compared against every value the snapshot holds for that
  #     field, and matches when any of them matches.
  #   * `contains`, `startswith`, `endswith` and `re` are case sensitive,
  #     because IOK builds its evaluator with `evaluator.CaseSensitive`.
  #     A matcher with no modifier is an exact, case *insensitive* comparison,
  #     which is sigma-go's behaviour: its case-sensitive comparator table has
  #     no entry for the default comparison.
  #
  # Usage:
  #
  #   rule = Iok::Rule.new(slug: "example", title: "Example", detection: {...})
  #   rule.matches?(snapshot)
  #
  class Rule
    class InvalidRule < StandardError; end

    # The fields a snapshot can supply. A matcher on any other field can never
    # match, so a rule that names one is rejected at compile time rather than
    # silently never firing.
    FIELDS = %w[title hostname dom html js css cookies headers requests].freeze

    COMPARATORS = %w[contains startswith endswith re].freeze

    attr_reader :slug, :title, :selections, :condition

    def initialize(slug:, title:, detection:)
      @slug = slug
      @title = title
      @selections = compile_selections(detection)
      @condition = compile_condition(detection)

      validate_references!
    end

    # @param snapshot [#values_for] anything that answers `values_for(field)`
    #   with an array of strings. Iok::PageSnapshot is the usual argument; a
    #   plain Hash of field => values works too.
    # @return [Boolean]
    def matches?(snapshot)
      condition.matches?(EvaluationContext.new(self, wrap(snapshot)))
    end

    private

    def wrap(snapshot)
      snapshot.respond_to?(:values_for) ? snapshot : HashSnapshot.new(snapshot)
    end

    def compile_selections(detection)
      unless detection.is_a?(Hash)
        raise InvalidRule, "detection block must be a mapping"
      end

      selections = detection.except("condition").transform_values do |body|
        Selection.new(body)
      end

      raise InvalidRule, "detection block has no selections" if selections.empty?

      selections
    end

    def compile_condition(detection)
      source = detection["condition"]
      raise InvalidRule, "detection block has no condition" if source.blank?

      Condition.new(source)
    rescue Condition::ParseError => e
      raise InvalidRule, "invalid condition: #{e.message}"
    end

    # A condition naming a selection that does not exist always evaluates to
    # false in Sigma. That is almost always a typo upstream, so treat it as a
    # broken rule instead of shipping one that can never fire.
    def validate_references!
      missing = condition.referenced_names.uniq - selections.keys
      return if missing.empty?

      raise InvalidRule, "condition references unknown selection(s): #{missing.join(', ')}"
    end

    # Resolves selection names for the condition, memoising each selection so a
    # name used twice is only evaluated once.
    class EvaluationContext
      def initialize(rule, snapshot)
        @rule = rule
        @snapshot = snapshot
        @results = {}
      end

      def names
        @rule.selections.keys
      end

      def matched?(name)
        return false unless @rule.selections.key?(name)

        @results.fetch(name) { @results[name] = @rule.selections[name].matches?(@snapshot) }
      end
    end

    # Adapts a plain Hash of field => value(s) to the snapshot interface.
    class HashSnapshot
      def initialize(fields)
        @fields = fields.transform_keys(&:to_s)
      end

      def values_for(field)
        Array(@fields[field.to_s]).map(&:to_s)
      end
    end

    # One named entry in the detection block.
    class Selection
      def initialize(body)
        @matchers = compile(body)
      end

      # A list of maps is an OR over the maps; a single map is an AND over its
      # field matchers.
      def matches?(snapshot)
        @matchers.any? do |group|
          group.all? { |matcher| matcher.matches?(snapshot) }
        end
      end

      private

      def compile(body)
        case body
        when Hash  then [ compile_group(body) ]
        when Array then body.map { |entry| compile_group(entry) }
        else
          raise InvalidRule, "selection must be a mapping or a list of mappings"
        end
      end

      def compile_group(entry)
        unless entry.is_a?(Hash)
          raise InvalidRule, "selection entry must be a mapping"
        end
        if entry.empty?
          raise InvalidRule, "selection entry is empty"
        end

        entry.map { |key, values| FieldMatcher.new(key, values) }
      end
    end

    # A single `field|modifier|...: value` line.
    class FieldMatcher
      attr_reader :field, :comparator, :values, :require_all

      def initialize(key, values)
        field, *modifiers = key.to_s.split("|")

        @field = field
        @require_all = modifiers.last == "all"
        modifiers = modifiers[0..-2] if @require_all
        @values = compile_values(values)
        @comparator = compile_comparator(modifiers)

        validate_field!
      end

      def matches?(snapshot)
        actual = snapshot.values_for(field)
        return false if actual.empty?

        if require_all
          values.all? { |expected| actual.any? { |value| compare(value, expected) } }
        else
          values.any? { |expected| actual.any? { |value| compare(value, expected) } }
        end
      end

      private

      def validate_field!
        return if FIELDS.include?(field)

        raise InvalidRule, "unknown field #{field.inspect}, expected one of #{FIELDS.join(', ')}"
      end

      def compile_comparator(modifiers)
        if modifiers.empty?
          return ->(actual, expected) { actual.casecmp?(expected) }
        end

        unless modifiers.one? && COMPARATORS.include?(modifiers.first)
          raise InvalidRule, "unsupported modifier(s) #{modifiers.join('|').inspect} on #{field}"
        end

        case modifiers.first
        when "contains"   then ->(actual, expected) { actual.include?(expected) }
        when "startswith" then ->(actual, expected) { actual.start_with?(expected) }
        when "endswith"   then ->(actual, expected) { actual.end_with?(expected) }
        when "re"         then regex_comparator
        end
      end

      # Patterns are compiled when the rule is, not on every comparison, so a
      # broken pattern fails the sync that introduced it rather than a domain
      # check months later. IOK's patterns are Go RE2 syntax, which for this
      # corpus is a subset of Ruby's.
      def regex_comparator
        compiled = values.index_with { |pattern| compile_regex(pattern) }

        ->(actual, expected) { compiled.fetch(expected).match?(actual) }
      end

      def compile_regex(pattern)
        Regexp.new(pattern)
      rescue RegexpError => e
        raise InvalidRule, "invalid regular expression #{pattern.inspect}: #{e.message}"
      end

      def compile_values(values)
        list = Array.wrap(values)
        raise InvalidRule, "no values for #{field}" if list.empty?

        list.map do |value|
          case value
          when String, Numeric, true, false then value.to_s
          else
            raise InvalidRule, "expected a scalar value for #{field}, got #{value.class}"
          end
        end
      end

      # Encoding differs between the rule (UTF-8 from YAML) and the snapshot
      # (whatever the site served). Comparing them directly raises
      # Encoding::CompatibilityError, so the snapshot normalises to UTF-8 and
      # anything still invalid is skipped rather than allowed to blow up the
      # whole check.
      def compare(actual, expected)
        comparator.call(actual, expected)
      rescue ArgumentError, Encoding::CompatibilityError
        false
      end
    end
  end
end
