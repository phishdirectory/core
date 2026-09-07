// Entry point for the importmap.
//
// Loading Turbo is what makes data-turbo-confirm work at all. Before this the
// attribute was present on 23 destructive actions and did nothing.
import "@hotwired/turbo-rails"
import "controllers"
