# frozen_string_literal: true

module Dashboard
  class DomainChecksController < BaseController
    def new
      @domain = nil
      @result = nil
    end

    def create
      domain = params[:domain]&.strip&.downcase

      if domain.blank?
        flash.now[:alert] = "Please enter a domain to check"
        return render :new
      end

      # Normalize domain (remove protocol, path, etc.)
      @domain = normalize_domain(domain)

      # Find or create the domain record
      phish_domain = Phish::Domain.find_or_create_by(domain: @domain)

      # Run the check if needed (stale or never checked)
      if phish_domain.needs_check?
        run_domain_check(phish_domain)
        phish_domain.reload
      end

      # Build result
      @result = {
        domain: @domain,
        verdict: phish_domain.classification || "unknown",
        confidence: phish_domain.confidence_score,
        sources: phish_domain.verdict&.sources_list || [],
        last_checked: phish_domain.last_checked_at,
        created_at: phish_domain.created_at
      }

      render :new
    end

    private

    def run_domain_check(phish_domain)
      service = Phish::AggregatorService.new
      result = service.check_domain(phish_domain.domain)

      # Update or create verdict
      verdict = phish_domain.verdict || Verdict.new
      verdict.update!(
        classification: result[:verdict],
        confidence_score: result[:confidence],
        sources: result[:details]&.dig(:service_results) || [],
        metadata: result[:details] || {}
      )

      phish_domain.update!(
        verdict: verdict,
        last_checked_at: Time.current
      )
    rescue StandardError => e
      Rails.logger.error("[DomainCheck] Failed to check #{phish_domain.domain}: #{e.message}")
      # Don't fail the request, just show unknown
    end

    def normalize_domain(domain)
      # Remove protocol
      domain = domain.sub(%r{\Ahttps?://}, "")
      # Remove path and query string
      domain = domain.split("/").first
      # Remove port
      domain = domain.split(":").first
      domain
    end
  end
end
