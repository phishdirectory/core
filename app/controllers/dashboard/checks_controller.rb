# frozen_string_literal: true

module Dashboard
  # One controller behind every dashboard lookup. The domain, email and phone
  # controllers were three copies of the same twenty lines, which is how they
  # drifted apart, and adding the long-advertised URL check meant a fourth.
  class ChecksController < BaseController
    Result = Struct.new(
      :value, :verdict, :confidence, :sources, :last_checked, :created_at,
      :details, :note, :failed,
      keyword_init: true
    ) do
      def failed? = failed
      def verdict_known? = verdict.present? && verdict != "unknown"
    end

    before_action :load_check_type

    def new
      @result = nil
      render :new
    end

    def create
      input = params[@check.param]

      if input.blank?
        flash.now[:alert] = "Enter #{@check.field_label.downcase} to check."
        return render :new
      end

      @value = @check.normalize(input)

      unless @check.valid?(@value)
        flash.now[:alert] = @check.invalid_message
        return render :new
      end

      @result = perform_check(input)
      render :new
    end

    private

    def load_check_type
      @check = Checks::Base.for(params[:type])
    end

    def perform_check(original_input)
      record = @check.find_or_create(@value)
      failed = false

      if record.needs_check?
        failed = !run_check(record)
        record.reload
      end

      Result.new(
        value: @value,
        verdict: record.classification || "unknown",
        confidence: record.confidence_score,
        sources: record.verdict&.sources_list || [],
        last_checked: record.last_checked_at,
        created_at: record.created_at,
        details: @check.details(record),
        note: @check.normalization_note(original_input, @value),
        failed: failed
      )
    end

    # A failed lookup and a lookup that genuinely found nothing used to render
    # the same "Unknown" badge, so an outage was indistinguishable from a clean
    # result. The caller needs to be able to tell those apart.
    def run_check(record)
      @check.run(record)
      true
    rescue StandardError => e
      Rails.logger.error("[#{@check.key.camelize}Check] #{@value}: #{e.class} #{e.message}")
      false
    end
  end
end
