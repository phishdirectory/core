import { Controller } from "@hotwired/stimulus"

// The scam category / subcategory picker on the classification form, plus the
// reference dialog that explains each category.
//
// Replaces a set of global functions wired up through inline onclick
// attributes. Those also built the subcategory list with innerHTML and string
// interpolation; this builds nodes and sets textContent, so a label
// containing markup cannot become markup.
export default class extends Controller {
  static targets = [
    "category",
    "subcategory",
    "notes",
    "modal",
    "modalContainer",
    "modalTitle",
    "modalDescription",
    "modalSubcategories"
  ]
  static values = { taxonomy: Array }

  connect() {
    this.previouslyFocused = null
    this.onKeydown = this.#onKeydown.bind(this)
    document.addEventListener("keydown", this.onKeydown)
    this.filterSubcategories()
  }

  disconnect() {
    document.removeEventListener("keydown", this.onKeydown)
    document.body.style.overflow = ""
  }

  // Only the subcategories belonging to the chosen category stay selectable.
  filterSubcategories() {
    const selected = this.categoryTarget.value
    this.subcategoryTarget.selectedIndex = 0

    this.subcategoryTarget.querySelectorAll("option[data-category]").forEach((option) => {
      const matches = Boolean(selected) && option.dataset.category === selected
      option.classList.toggle("hidden", !matches)
      option.disabled = !matches
    })
  }

  // ----------------------------------------------------------------- dialog

  get isOpen() {
    return !this.modalTarget.classList.contains("hidden")
  }

  openCategory(event) {
    const value = event.params.category ?? event.currentTarget.dataset.category
    const category = this.taxonomyValue.find((entry) => entry.value === value)
    if (!category) return

    this.previouslyFocused = document.activeElement
    this.modalTitleTarget.textContent = category.label
    this.modalDescriptionTarget.textContent = category.description || ""
    this.modalSubcategoriesTarget.replaceChildren(
      ...(category.subcategories || []).map((sub) => this.#subcategoryButton(category.value, sub))
    )

    this.modalTarget.classList.remove("hidden")
    this.modalTarget.setAttribute("aria-hidden", "false")
    document.body.style.overflow = "hidden"

    requestAnimationFrame(() => {
      this.modalContainerTarget.classList.remove("scale-95", "opacity-0")
      this.modalContainerTarget.classList.add("scale-100", "opacity-100")
      this.modalSubcategoriesTarget.querySelector("button")?.focus()
    })
  }

  close() {
    if (!this.isOpen) return

    this.modalContainerTarget.classList.remove("scale-100", "opacity-100")
    this.modalContainerTarget.classList.add("scale-95", "opacity-0")
    this.modalTarget.setAttribute("aria-hidden", "true")

    setTimeout(() => {
      this.modalTarget.classList.add("hidden")
      document.body.style.overflow = ""
      this.previouslyFocused?.focus?.()
      this.previouslyFocused = null
    }, 150)
  }

  closeOnBackdrop(event) {
    if (event.target === event.currentTarget) this.close()
  }

  #onKeydown(event) {
    if (event.key === "Escape" && this.isOpen) {
      event.preventDefault()
      this.close()
    }
  }

  #subcategoryButton(categoryValue, sub) {
    const button = document.createElement("button")
    button.type = "button"
    button.className =
      "w-full text-left px-3 py-2 bg-surface-200/50 rounded hover:bg-surface-300/50 transition-colors group focus:outline-none focus:ring-2 focus:ring-accent"

    const row = document.createElement("div")
    row.className = "flex items-center justify-between"

    const label = document.createElement("div")
    label.className = "text-sm font-medium text-surface-800 group-hover:text-surface-900"
    label.textContent = sub.label
    row.appendChild(label)

    const description = document.createElement("div")
    description.className = "text-xs text-surface-500 mt-0.5"
    description.textContent = sub.description || ""

    button.append(row, description)
    button.addEventListener("click", () => this.#choose(categoryValue, sub.value))

    return button
  }

  #choose(categoryValue, subcategoryValue) {
    this.categoryTarget.value = categoryValue
    this.filterSubcategories()
    this.subcategoryTarget.value = subcategoryValue
    this.close()

    // Land the cursor where the person is going to type next.
    setTimeout(() => this.notesTarget?.focus(), 200)
  }
}
