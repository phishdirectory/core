# frozen_string_literal: true

module Admin
  class ApiRequestsController < BaseController
    def index
      @requests = ApiRequest.recent.includes(:authenticatable, :user)

      # Status filter
      case params[:status]
      when "success"
        @requests = @requests.successful
      when "client_error"
        @requests = @requests.client_errors
      when "server_error"
        @requests = @requests.server_errors
      end

      # Time filter
      case params[:time]
      when "today"
        @requests = @requests.today
      when "week"
        @requests = @requests.this_week
      end

      # Slow requests filter
      if params[:slow] == "true"
        threshold = params[:threshold].present? ? params[:threshold].to_i : 1000
        @requests = @requests.slow(threshold)
      end

      # Auth type filter
      case params[:auth_type]
      when "user"
        @requests = @requests.for_user_keys
      when "service"
        @requests = @requests.for_service_keys
      end

      # Path filter
      if params[:path].present?
        @requests = @requests.by_path(params[:path])
      end

      # Method filter
      if params[:method].present?
        @requests = @requests.by_method(params[:method])
      end

      @requests = @requests.page(params[:page])
    end

    def show
      @request = ApiRequest.find(params[:id])
    end
  end
end
