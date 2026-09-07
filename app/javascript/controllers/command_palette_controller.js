import { Controller } from "@hotwired/stimulus"

// Quick search palette, opened with Cmd/Ctrl-K or the search button.
//
// This was previously an IIFE inline in the partial. With Turbo Drive running,
// that script re-executes on every navigation and each run added another
// keydown listener to `document`, so the shortcut would fire N times after N
// page visits. A controller gets torn down on disconnect, which is the whole
// reason this needs to be one.
export default class extends Controller {
  static targets = ["modal", "container", "input", "content", "empty", "loading"]
  static values = { searchUrl: String, isAdmin: Boolean }

  BADGE_COLORS = {
    emerald: "bg-success/10 text-success",
    amber: "bg-warning/10 text-warning",
    red: "bg-danger/10 text-danger",
    cyan: "bg-accent/10 text-accent",
    purple: "bg-purple-500/10 text-purple-400",
    slate: "bg-surface-300 text-surface-600"
  }

  connect() {
    this.items = this.#loadItems()
    this.filtered = this.items
    this.selectedIndex = 0
    this.searchTimeout = null
    this.previouslyFocused = null

    this.onKeydown = this.#onGlobalKeydown.bind(this)
    document.addEventListener("keydown", this.onKeydown)
  }

  disconnect() {
    document.removeEventListener("keydown", this.onKeydown)
    clearTimeout(this.searchTimeout)
  }

  // ---------------------------------------------------------------- opening

  get isOpen() {
    return !this.modalTarget.classList.contains("hidden")
  }

  toggle(event) {
    event?.preventDefault()
    this.isOpen ? this.close() : this.open()
  }

  open() {
    this.previouslyFocused = document.activeElement
    this.modalTarget.classList.remove("hidden")
    this.modalTarget.setAttribute("aria-hidden", "false")

    requestAnimationFrame(() => {
      this.containerTarget.classList.remove("scale-95", "opacity-0")
      this.containerTarget.classList.add("scale-100", "opacity-100")
      this.inputTarget.focus()
      this.inputTarget.value = ""
      this.filtered = this.items
      this.selectedIndex = 0
      this.#render(this.items)
    })
  }

  close() {
    this.containerTarget.classList.remove("scale-100", "opacity-100")
    this.containerTarget.classList.add("scale-95", "opacity-0")
    this.modalTarget.setAttribute("aria-hidden", "true")

    setTimeout(() => {
      this.modalTarget.classList.add("hidden")
      // Send focus back where it came from, or a keyboard user is dumped at
      // the top of the document every time they dismiss the palette.
      this.previouslyFocused?.focus?.()
      this.previouslyFocused = null
    }, 150)
  }

  closeOnBackdrop(event) {
    if (event.target === event.currentTarget) this.close()
  }

  // --------------------------------------------------------------- keyboard

  #onGlobalKeydown(event) {
    if ((event.metaKey || event.ctrlKey) && event.key === "k") {
      event.preventDefault()
      this.toggle()
      return
    }

    if (event.key === "Escape" && this.isOpen) {
      event.preventDefault()
      this.close()
    }
  }

  // Arrow keys, Enter and Tab while the input has focus. Tab is trapped so
  // focus cannot wander behind the open dialog.
  navigate(event) {
    switch (event.key) {
      case "ArrowDown":
        event.preventDefault()
        if (this.selectedIndex < this.filtered.length - 1) {
          this.selectedIndex++
          this.#updateSelection()
        }
        break
      case "ArrowUp":
        event.preventDefault()
        if (this.selectedIndex > 0) {
          this.selectedIndex--
          this.#updateSelection()
        }
        break
      case "Enter":
        event.preventDefault()
        this.#select()
        break
      case "Tab":
        event.preventDefault()
        break
    }
  }

  // ----------------------------------------------------------------- search

  search(event) {
    clearTimeout(this.searchTimeout)
    const query = event.target.value.trim()
    this.searchTimeout = setTimeout(() => this.#runSearch(query), 150)
  }

  #runSearch(query) {
    if (!query) return this.#render(this.items)

    const local = this.#filterLocal(query)

    if (!this.isAdminValue || !this.searchUrlValue) return this.#render(local)

    this.loadingTarget.classList.remove("hidden")
    this.contentTarget.classList.add("hidden")

    fetch(`${this.searchUrlValue}?q=${encodeURIComponent(query)}`, {
      headers: { Accept: "application/json" }
    })
      .then((response) => response.json())
      .then((data) => this.#render(local.concat(data.results || [])))
      .catch(() => this.#render(local))
  }

  #filterLocal(query) {
    const needle = query.toLowerCase()
    return this.items.filter((item) => {
      const haystack = `${item.name} ${item.subtitle || ""} ${item.keywords || ""}`
      return haystack.toLowerCase().includes(needle)
    })
  }

  // --------------------------------------------------------------- rendering

  #render(items) {
    this.filtered = items
    this.selectedIndex = 0
    this.contentTarget.replaceChildren()
    this.loadingTarget.classList.add("hidden")

    if (items.length === 0) {
      this.contentTarget.classList.add("hidden")
      this.emptyTarget.classList.remove("hidden")
      return
    }

    this.emptyTarget.classList.add("hidden")
    this.contentTarget.classList.remove("hidden")

    let section = null
    items.forEach((item, index) => {
      const itemSection = item.section || "Results"
      if (itemSection !== section) {
        this.contentTarget.appendChild(this.#sectionHeader(itemSection))
        section = itemSection
      }
      this.contentTarget.appendChild(this.#itemElement(item, index))
    })

    this.#updateSelection()
  }

  #sectionHeader(name) {
    const header = document.createElement("div")
    header.className =
      "px-4 py-2 text-[10px] font-semibold text-surface-500 uppercase tracking-wider bg-surface-200/50 sticky top-0"
    header.setAttribute("role", "presentation")
    header.textContent = name
    return header
  }

  #itemElement(item, index) {
    const el = document.createElement("div")
    const base = "command-k-item flex items-center gap-3 py-2.5 cursor-pointer transition-colors"

    if (item.role === "admin") {
      el.className = `${base} pl-3 pr-4 border-l-2 border-purple-500`
    } else if (item.role === "trusted") {
      el.className = `${base} pl-3 pr-4 border-l-2 border-cyan-500`
    } else {
      el.className = `${base} px-4`
    }

    el.setAttribute("role", "option")
    el.setAttribute("aria-selected", "false")
    el.dataset.index = index

    if (item.role === "admin" || item.role === "trusted") {
      const badge = document.createElement("span")
      const admin = item.role === "admin"
      badge.className = `px-1.5 py-0.5 text-[10px] rounded font-medium ${
        admin ? "bg-purple-500/20 text-purple-400" : "bg-cyan-500/20 text-cyan-400"
      }`
      badge.textContent = admin ? "Admin" : "Trusted"
      el.appendChild(badge)
    }

    const text = document.createElement("div")
    text.className = "flex-1 min-w-0"

    const name = document.createElement("div")
    name.className = "text-sm font-medium text-surface-800"
    name.textContent = item.name || ""
    text.appendChild(name)

    if (item.subtitle) {
      const subtitle = document.createElement("div")
      subtitle.className = "text-xs text-surface-500 truncate"
      subtitle.textContent = item.subtitle
      text.appendChild(subtitle)
    }

    el.appendChild(text)

    if (item.badge) {
      const badge = document.createElement("span")
      badge.className = `px-1.5 py-0.5 text-[10px] rounded font-medium ${
        this.BADGE_COLORS[item.badge_color] || this.BADGE_COLORS.slate
      }`
      badge.textContent = item.badge
      el.appendChild(badge)
    }

    el.addEventListener("mouseenter", () => {
      this.selectedIndex = index
      this.#updateSelection()
    })
    el.addEventListener("click", () => {
      this.selectedIndex = index
      this.#select()
    })

    return el
  }

  #updateSelection() {
    this.contentTarget.querySelectorAll(".command-k-item").forEach((el, index) => {
      const selected = index === this.selectedIndex
      el.classList.toggle("bg-surface-200", selected)
      el.setAttribute("aria-selected", selected ? "true" : "false")
      if (selected) el.scrollIntoView({ block: "nearest" })
    })
  }

  #select() {
    const item = this.filtered[this.selectedIndex]
    if (!item?.url) return

    this.close()

    if (item.method === "delete") {
      this.#submitDelete(item.url)
    } else {
      Turbo.visit(item.url)
    }
  }

  #submitDelete(url) {
    const form = document.createElement("form")
    form.method = "post"
    form.action = url

    const method = document.createElement("input")
    method.type = "hidden"
    method.name = "_method"
    method.value = "delete"

    const token = document.createElement("input")
    token.type = "hidden"
    token.name = "authenticity_token"
    token.value = document.querySelector('meta[name="csrf-token"]')?.content || ""

    form.append(method, token)
    document.body.appendChild(form)
    form.requestSubmit()
  }

  #loadItems() {
    const script = this.element.querySelector('[data-command-palette-data]')
    if (!script) return []

    const data = JSON.parse(script.textContent)
    return [
      ...(data.navigation || []),
      ...(data.trusted_navigation || []),
      ...(data.admin_navigation || [])
    ]
  }
}
