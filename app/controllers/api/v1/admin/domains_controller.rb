# frozen_string_literal: true

module Api
  module V1
    module Admin
      class DomainsController < Api::V1::BaseController
        before_action :require_admin!

        # POST /api/v1/admin/domain/bulk_import
        def bulk_import
          domains = Array(params[:domains]).map { |d| d&.strip&.downcase }.compact.uniq

          if domains.empty?
            return render json: { error: "Missing required parameter: domains" }, status: :bad_request
          end

          # Queue the import job
          job = BulkDomainImportJob.perform_later(domains, current_user.id)

          render json: {
            accepted: domains.size,
            job_id: job.job_id,
            message: "Domains queued for processing"
          }, status: :accepted
        end

        private

        def require_admin!
          return if current_user&.admin?

          render json: { error: "Admin access required" }, status: :forbidden
        end
      end
    end
  end
end
