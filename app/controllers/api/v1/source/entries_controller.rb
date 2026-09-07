# frozen_string_literal: true

module Api
  module V1
    module Source
      # Ingestion endpoints for trusted sources.
      #
      # Every other check endpoint answers the question "what do you know about
      # this value?". These answer the opposite one: the caller already knows,
      # and we record what it tells us. A submission upserts the record and
      # replaces its verdict without running Phish::AggregatorService.
      #
      # Only a service key flagged trusted_source may call these. A user API key
      # never can, whatever the user's access level.
      class EntriesController < Api::V1::BaseController
        before_action :require_trusted_source!

        # POST /api/v1/source/domains
        def domains
          upsert("domain", :domains)
        end

        # POST /api/v1/source/urls
        def urls
          upsert("url", :urls)
        end

        # POST /api/v1/source/emails
        def emails
          upsert("email", :emails)
        end

        # POST /api/v1/source/phone_numbers
        def phone_numbers
          upsert("phone_number", :phone_numbers)
        end

        private

        def upsert(type, param_key)
          entries = Array(params[param_key])

          if entries.empty?
            return render json: { error: "Missing required parameter: #{param_key}" }, status: :bad_request
          end

          if entries.size > TrustedSourceUpsertService::MAX_ENTRIES
            return render json: {
              error: "Maximum #{TrustedSourceUpsertService::MAX_ENTRIES} entries per request",
              received: entries.size
            }, status: :bad_request
          end

          render json: TrustedSourceUpsertService.call(
            type: type,
            entries: entries,
            service: current_service,
            default_classification: params[:classification],
            default_confidence: params[:confidence]
          )
        end

        # A trusted source writes to the database, so this checks the key rather
        # than the service: a partner may hold a read key and an ingestion key,
        # and only the second one gets here.
        def require_trusted_source!
          return if current_service_key&.trusted_source_writer?

          render json: {
            error: "Trusted source access required",
            hint: "This endpoint needs a service key marked as a trusted source"
          }, status: :forbidden
        end
      end
    end
  end
end
