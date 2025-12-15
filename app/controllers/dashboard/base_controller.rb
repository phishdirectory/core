# frozen_string_literal: true

module Dashboard
  class BaseController < ApplicationController
    before_action :authenticate_user!

    layout "dashboard"
  end
end
