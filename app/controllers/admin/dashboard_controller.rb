# frozen_string_literal: true

module Admin
  class DashboardController < BaseController
    def index
      @users_count = User.count
      @services_count = Service.count
      @domains_count = Phish::Domain.count
      @online_users = User.currently_online.count
    end
  end
end
