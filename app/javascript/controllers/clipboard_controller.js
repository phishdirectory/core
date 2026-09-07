import { Controller } from "@hotwired/stimulus"

// Copies a value to the clipboard and confirms it on the button itself.
//
// Used for the one-time reveal of a freshly created API key, which is the only
// moment that value exists.
export default class extends Controller {
  static targets = ["source", "button"]
  static values = {
    successLabel: { type: String, default: "Copied" },
    resetAfter: { type: Number, default: 2000 }
  }

  connect() {
    // The reveal is the reason the page was loaded; put it in view.
    this.element.scrollIntoView({ behavior: "smooth", block: "center" })
  }

  disconnect() {
    clearTimeout(this.resetTimeout)
  }

  async copy() {
    const value = this.sourceTarget.textContent.trim()

    try {
      await navigator.clipboard.writeText(value)
      this.#confirm()
    } catch {
      // Clipboard API needs a secure context and permission. Fall back rather
      // than leaving the user with a button that silently does nothing.
      this.#copyBySelection(value) ? this.#confirm() : this.#reportFailure()
    }
  }

  #copyBySelection(value) {
    const textarea = document.createElement("textarea")
    textarea.value = value
    textarea.setAttribute("readonly", "")
    textarea.style.position = "fixed"
    textarea.style.opacity = "0"
    document.body.appendChild(textarea)
    textarea.select()

    let copied = false
    try {
      copied = document.execCommand("copy")
    } catch {
      copied = false
    }

    document.body.removeChild(textarea)
    return copied
  }

  #confirm() {
    const button = this.buttonTarget
    this.originalLabel ??= button.textContent

    button.textContent = this.successLabelValue
    button.classList.add("bg-success")
    button.classList.remove("bg-surface-900")

    clearTimeout(this.resetTimeout)
    this.resetTimeout = setTimeout(() => {
      button.textContent = this.originalLabel
      button.classList.remove("bg-success")
      button.classList.add("bg-surface-900")
    }, this.resetAfterValue)
  }

  #reportFailure() {
    this.buttonTarget.textContent = "Press Ctrl+C to copy"
    this.sourceTarget.focus?.()
  }
}
