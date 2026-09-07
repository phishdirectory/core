import { Controller } from "@hotwired/stimulus"

// Off-canvas sidebar for narrow screens.
//
// The rail was 224px wide, fixed, with no responsive variant at any
// breakpoint, and the main content carried a matching left margin. On a 375px
// phone that left about 150px for the page itself.
export default class extends Controller {
  static targets = ["panel", "backdrop", "toggle"]

  connect() {
    this.onKeydown = this.#onKeydown.bind(this)
    document.addEventListener("keydown", this.onKeydown)

    // Turbo keeps the DOM between visits, so a sidebar opened before
    // navigating would still be open on the next page.
    this.close()
  }

  disconnect() {
    document.removeEventListener("keydown", this.onKeydown)
    document.body.classList.remove("overflow-hidden")
  }

  get isOpen() {
    return !this.panelTarget.classList.contains("-translate-x-full")
  }

  toggle() {
    this.isOpen ? this.close() : this.open()
  }

  open() {
    this.panelTarget.classList.remove("-translate-x-full")
    this.backdropTarget.classList.remove("hidden")
    this.toggleTarget?.setAttribute("aria-expanded", "true")
    document.body.classList.add("overflow-hidden")
  }

  close() {
    this.panelTarget.classList.add("-translate-x-full")
    this.backdropTarget.classList.add("hidden")
    this.toggleTarget?.setAttribute("aria-expanded", "false")
    document.body.classList.remove("overflow-hidden")
  }

  #onKeydown(event) {
    if (event.key === "Escape" && this.isOpen) this.close()
  }
}
