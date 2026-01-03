# frozen_string_literal: true

module Admin
  class PhishUrlsController < BaseController
    def index
      @urls = Phish::Url.includes(:verdict)
                        .order(created_at: :desc)
                        .page(params[:page])
    end

    def show
      @url = Phish::Url.find_by_public_id!(params[:id])
      @xarf_report = generate_xarf_report(@url)
    end

    private

    def generate_xarf_report(url)
      generator = Xarf::ReportGenerator.new
      report = generator.generate_for_url(url)
      return nil if report[:error]

      JSON.pretty_generate(report)
    end
  end
end
