# frozen_string_literal: true

module Iok
  # The enabled indicators, compiled once and reused.
  #
  # There are a few hundred rules and every domain check evaluates all of them,
  # so parsing each condition and regular expression per check would dominate
  # the cost of the service. Compiled rules are held per process and refreshed
  # when the table changes, which the sync job only does once a day.
  class RuleSet
    class << self
      # @return [Iok::RuleSet] the current rule set, rebuilt if the table moved
      def current
        version = version_token

        mutex.synchronize do
          @cached = nil if @version != version
          @version = version
          @cached ||= build
        end
      end

      # Drops the memoised rule set. Called by the sync job, and by tests.
      def reset!
        mutex.synchronize do
          @cached = nil
          @version = nil
        end
      end

      private

      def mutex
        @mutex ||= Mutex.new
      end

      # Cheap enough to run per check: one aggregate over a small table. Count
      # catches deletions, the timestamp catches edits, so between them any
      # change to the enabled set invalidates the cache.
      def version_token
        Iok::Indicator.enabled.pick(Arel.sql("COUNT(*), MAX(updated_at)"))
      end

      def build
        indicators = Iok::Indicator.enabled.order(:slug).to_a
        compiled = indicators.filter_map { |indicator| compile(indicator) }

        new(compiled)
      end

      # An indicator whose detection block stopped compiling (a hand edit, or a
      # schema change upstream) is skipped rather than allowed to raise inside
      # an unrelated domain check.
      def compile(indicator)
        [ indicator, indicator.rule ]
      rescue Iok::Rule::InvalidRule => e
        Rails.logger.warn("[iok] skipping indicator #{indicator.slug}: #{e.message}")
        nil
      end
    end

    attr_reader :entries

    def initialize(entries)
      @entries = entries
    end

    def size
      entries.size
    end

    def empty?
      entries.empty?
    end

    # @param snapshot [Iok::PageSnapshot]
    # @return [Array<Iok::Indicator>] every indicator whose rule matched
    def matches(snapshot)
      entries.filter_map do |indicator, rule|
        indicator if safely_matches?(rule, indicator, snapshot)
      end
    end

    private

    # One rule raising must not lose the verdicts of the other few hundred.
    def safely_matches?(rule, indicator, snapshot)
      rule.matches?(snapshot)
    rescue StandardError => e
      Rails.logger.warn("[iok] indicator #{indicator.slug} raised: #{e.class}: #{e.message}")
      false
    end
  end
end
