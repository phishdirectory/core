# frozen_string_literal: true

module Admin
  class PhishDomainsController < BaseController
    def index
      @domains = Phish::Domain.includes(:verdict)
                              .order(created_at: :desc)
                              .page(params[:page])
    end

    def show
      @domain = Phish::Domain.find_by_public_id!(params[:id])
      @xarf_report = generate_xarf_report(@domain)
    end

    private

    def generate_xarf_report(domain)
      generator = Xarf::ReportGenerator.new
      report = generator.generate_for_domain(domain)
      return nil if report[:error]

      JSON.pretty_generate(report)
    end
  end
end
