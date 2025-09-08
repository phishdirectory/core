# frozen_string_literal: true

module Api
  class BaseController < ApplicationController
    include ApiVersioning
    include ApiRateLimiting
    include ApiAuthentication

    # Skip default web authentication and tracking for API
    skip_before_action :authenticate_user!
    skip_before_action :track_user_session
    
    # Skip CSRF protection for API requests
    protect_from_forgery with: :null_session

    # Set JSON as default response format
    before_action :set_default_format

    # Handle common exceptions
    rescue_from ActiveRecord::RecordNotFound, with: :render_not_found
    rescue_from ActiveRecord::RecordInvalid, with: :render_unprocessable_entity
    rescue_from ActionController::ParameterMissing, with: :render_bad_request

    private

    def set_default_format
      request.format = :json
    end

    def render_success(data = {}, status = :ok)
      render json: {
        success: true,
        data: data
      }, status: status
    end

    def render_error(message, status = :bad_request, errors = [])
      render json: {
        success: false,
        error: {
          message: message,
          details: errors
        }
      }, status: status
    end

    def render_not_found(exception = nil)
      render_error(
        exception&.message || "Resource not found",
        :not_found
      )
    end

    def render_unprocessable_entity(exception)
      render_error(
        "Validation failed",
        :unprocessable_entity,
        exception.record.errors.full_messages
      )
    end

    def render_bad_request(exception)
      render_error(
        exception.message,
        :bad_request
      )
    end

    def paginate_collection(collection, page: nil, per_page: nil)
      page = (page || params[:page] || 1).to_i
      per_page = (per_page || params[:per_page] || 25).to_i
      per_page = [per_page, 100].min # Cap at 100 items per page

      offset = (page - 1) * per_page
      paginated = collection.limit(per_page).offset(offset)
      
      {
        data: paginated,
        pagination: {
          current_page: page,
          per_page: per_page,
          total_pages: (collection.count.to_f / per_page).ceil,
          total_count: collection.count
        }
      }
    end
  end
end