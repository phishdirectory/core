# frozen_string_literal: true

module Dashboard
  class ClassificationsController < BaseController
    before_action :require_trusted!
    before_action :set_classifiable, only: [:show, :create, :mark_clean, :skip]

    # GET /dashboard/classifications
    # Shows the classification queue for the current user
    def index
      @queue = classification_queue
      @next_item = next_item
      @my_recent_classifications = current_user.scam_classifications
        .includes(:classifiable)
        .order(created_at: :desc)
        .limit(10)
      @stats = classification_stats
    end

    # GET /dashboard/classifications/:type/:id
    # Shows a single item to classify
    # Note: We don't show existing classifications to prevent bias
    def show
      if @classifiable.classified_by?(current_user)
        flash[:notice] = "You have already classified this item"
        redirect_to dashboard_classifications_path
        return
      end

      @taxonomy = Scam.taxonomy_for_select
    end

    # POST /dashboard/classifications/:type/:id
    # Submit a classification
    def create
      if @classifiable.classified_by?(current_user)
        flash[:alert] = "You have already classified this item"
        redirect_to next_or_index
        return
      end

      unless @classifiable.classifiable?
        flash[:alert] = "This item cannot be classified (not phishing or suspicious)"
        redirect_to next_or_index
        return
      end

      begin
        @classifiable.add_classification!(
          user: current_user,
          category: params[:scam_category],
          subcategory: params[:scam_subcategory].presence,
          notes: params[:notes].presence
        )
        flash[:success] = "Classification submitted successfully"
      rescue ArgumentError => e
        flash[:alert] = e.message
      end

      # Redirect based on which button was clicked
      if params[:commit] == "finish"
        redirect_to dashboard_classifications_path
      else
        redirect_to next_or_index
      end
    end

    # POST /dashboard/classifications/:type/:id/mark_clean
    # Mark a suspicious item as clean (staff override)
    def mark_clean
      unless @classifiable.verdict&.suspicious?
        flash[:alert] = "Only suspicious items can be marked as clean"
        redirect_to next_or_index
        return
      end

      if @classifiable.marked_clean?
        flash[:alert] = "This item has already been marked as clean"
        redirect_to next_or_index
        return
      end

      @classifiable.mark_as_clean!(user: current_user)
      flash[:success] = "Item marked as clean"

      # Redirect based on which button was clicked
      if params[:commit] == "finish"
        redirect_to dashboard_classifications_path
      else
        redirect_to next_or_index
      end
    end

    # POST /dashboard/classifications/:type/:id/skip
    # Skip this item (moves it to the back of the user's queue)
    def skip
      @classifiable.record_skip!(current_user)
      flash[:notice] = "Item skipped - it will appear later in your queue"
      redirect_to next_or_index
    end

    private

    def require_trusted!
      unless current_user.trusted?
        flash[:alert] = "You must be a trusted user or higher to access classifications"
        redirect_to dashboard_root_path
      end
    end

    def set_classifiable
      type = params[:type]
      id = params[:id]

      @classifiable = case type
      when "domain"
        Phish::Domain.find_by_public_id!(id)
      when "url"
        Phish::Url.find_by_public_id!(id)
      else
        raise ActiveRecord::RecordNotFound, "Unknown classifiable type: #{type}"
      end
    end

    def classification_queue
      # Get both domains and URLs that need classification
      domains = Phish::Domain.classification_queue_for(current_user, limit: 5)
      urls = Phish::Url.classification_queue_for(current_user, limit: 5)

      # Combine and sort by created_at
      (domains.to_a + urls.to_a).sort_by(&:created_at).first(10)
    end

    def classification_stats
      {
        total_domains_pending: Phish::Domain.needs_classification.count,
        total_urls_pending: Phish::Url.needs_classification.count,
        my_classifications_today: current_user.scam_classifications.where("created_at >= ?", Time.current.beginning_of_day).count,
        my_total_classifications: current_user.scam_classifications.count
      }
    end

    def next_item
      # Get the next item from the queue (prioritize domains, then URLs)
      domain = Phish::Domain.classification_queue_for(current_user, limit: 1).first
      return domain if domain

      Phish::Url.classification_queue_for(current_user, limit: 1).first
    end

    def next_or_index
      item = next_item
      if item
        type = item.is_a?(Phish::Domain) ? "domain" : "url"
        dashboard_classification_path(type: type, id: item.public_id)
      else
        dashboard_classifications_path
      end
    end
  end
end
