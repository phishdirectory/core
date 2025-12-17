# frozen_string_literal: true

class DocsController < ApplicationController
  layout "docs"

  def index
    render :index
  end

  def show
    template = "docs/#{params[:page]}"
    if template_exists?(template)
      render template
    else
      redirect_to docs_path, alert: "Documentation page not found."
    end
  end
end
