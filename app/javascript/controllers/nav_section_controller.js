import { Controller } from "@hotwired/stimulus"

// One collapsible section of the admin sidebar. Whether it is open is
// remembered per section in localStorage.
//
// The previous inline version re-scanned the whole sidebar on every
// turbo:load and guarded against double-binding with a dataset flag. One
// controller instance per section does the same job without the bookkeeping.
export default class extends Controller {
  static targets = ["content", "chevron", "toggle"]
  static values = {
    name: String,
    defaultCollapsed: { type: Boolean, default: false }
  }

  static STORAGE_KEY = "admin_nav_collapsed_v2"

  connect() {
    this.collapsed = this.#storedState() ?? this.defaultCollapsedValue
    this.#apply({ animate: false })
  }

  toggle() {
    this.collapsed = !this.collapsed
    this.#apply({ animate: true })
    this.#persist()
  }

  #apply({ animate }) {
    const content = this.contentTarget

    // Height is animated from a measured pixel value, so transitions are
    // suppressed for the initial paint to avoid a visible unfurl on load.
    if (!animate) content.style.transition = "none"

    content.style.maxHeight = this.collapsed ? "0" : `${content.scrollHeight}px`
    content.style.opacity = this.collapsed ? "0" : "1"

    if (this.hasChevronTarget) {
      this.chevronTarget.style.transform = this.collapsed ? "rotate(-90deg)" : "rotate(0deg)"
    }

    // aria-expanded belongs on the control, not on the region it controls.
    if (this.hasToggleTarget) {
      this.toggleTarget.setAttribute("aria-expanded", this.collapsed ? "false" : "true")
    }

    if (!animate) {
      // Force a reflow before restoring transitions.
      void content.offsetHeight
      content.style.transition = ""
    }
  }

  // localStorage is unavailable in private modes and can throw on access, so
  // every read and write is guarded. A failure just means the section opens in
  // its default state.
  #allState() {
    try {
      return JSON.parse(localStorage.getItem(this.constructor.STORAGE_KEY)) || {}
    } catch {
      return {}
    }
  }

  #storedState() {
    const state = this.#allState()
    return Object.hasOwn(state, this.nameValue) ? state[this.nameValue] : null
  }

  #persist() {
    try {
      const state = this.#allState()
      state[this.nameValue] = this.collapsed
      localStorage.setItem(this.constructor.STORAGE_KEY, JSON.stringify(state))
    } catch {
      // Preference is not critical; losing it is fine.
    }
  }
}
