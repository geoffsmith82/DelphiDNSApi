# Delphi DNS API Library & Demonstration App

A **Delphi FMX application** for managing DNS zones and records via cloud provider APIs. The core of this project is a **Delphi DNS API library** that provides a consistent interface to multiple DNS provider APIs, with the FMX app serving primarily as a demonstration and test tool for the API layer. The initial release supports **Vultr Cloud DNS**, with a modular architecture designed to support additional providers such as **Cloudflare**, **AWS Route53**, **Google Cloud DNS**, and others in future versions.

---

## 🚀 Features

- **Manage DNS zones** from supported providers.
- **Add and delete zones** directly from the UI.
- **View and manage DNS records** for each zone.
- **Add, edit, and delete DNS records** through provider APIs.
- **API key setup panel** for securely storing provider credentials.
- **Modular provider system** to support multiple DNS APIs.
- **Modern FMX UI** with animated modal panels and responsive layouts.
- **Cross-platform support** — Windows, macOS, and mobile.

---

## 🧩 Components Overview

| Component | Purpose |
|------------|----------|
| **MainForm** | Main application window hosting all layouts and controls. |
| **TabControl** | Switches between *Zones* and *Records* views. |
| **ZonesList / RecordsList** | Displays DNS zones and records retrieved from the selected provider. |
| **RecordEditPanel / ZoneAddPanel** | Modal-style panels for creating or editing zones and records. |
| **SetupPanel** | Used for API key configuration. |
| **SlideIn / SlideOut / FadeIn / FadeOut** | Form-level animations for panel transitions. |
| **StatusBar** | Displays current status messages and background task indicators. |

---

## ⚙️ Requirements

- **Delphi 11+ (FMX Framework)**
- API credentials for one or more supported providers (e.g., **Vultr API key**)
- **Internet connection** for API communication

---

## 🧠 Architecture

- **Core Focus:** A reusable **DNS API abstraction layer** written in Delphi that defines provider-neutral interfaces for DNS operations.
- The accompanying **FMX app** demonstrates the use of this API in a GUI context.
- Built around **FMX** visual components and **TRESTClient** for RESTful communication.
- Extensible architecture: each DNS provider implements a shared interface defined in `DNS.Base`.
- Asynchronous operations (via `TTask` and `TThread.Synchronize`) ensure a responsive UI.
- Clean separation of concerns between UI, provider logic, and domain model.

---

## 🔑 Setup Instructions

1. Open the project in **Delphi 11+**.
2. Run the application.
3. When prompted, enter your **Vultr API key** (or another provider key, when available).
4. Manage zones and records via the intuitive tabbed interface.
5. Use the record and zone panels to create or modify entries.

---

## 🧩 Planned Multi-Provider Support

This project is being expanded to support additional DNS APIs. Planned providers include:

| Provider | Status |
|-----------|---------|
| **Vultr DNS** | ✅ Implemented |
| **Cloudflare DNS** | ⏳ Planned |
| **AWS Route53** | ⏳ Planned |
| **Microsoft Azure DNS** | ⏳ Planned |
| **Google Cloud DNS** | ⏳ Planned |
| **DigitalOcean DNS** | ⏳ Planned |

Each provider will implement a shared interface (`IDNSProvider`) to ensure consistency across operations like listing zones, managing records, and authentication.

---

## 🎨 UI Details

- **MainLayout** — Holds header, tabs, and status bar.
- **HeaderLayout** — Blue banner with app title.
- **Zones / Records Layouts** — Toolbars and list views for managing data.
- **SetupPanel / RecordEditPanel / ZoneAddPanel** — Modal dialogs with rounded corners and shadow effects.
- **Animations** — `TFloatAnimation` elements for slide and fade transitions.

---

## 📦 File Overview

| File | Description |
|------|-------------|
| `DNS.UI.Main.pas` | Main application form logic, event handling, and provider integration. |
| `DNS.UI.Main.fmx` | UI layout definition for the FMX form. |
| `DNS.Base.pas` | Defines abstract interfaces and shared models for DNS providers. |
| `DNS.Vultr.pas` | Implements the Vultr-specific API provider. |
| `DNS.Helpers.pas` | Utility functions for JSON parsing and REST handling. |

---

## 🧪 Future Enhancements

- Multi-provider support (Cloudflare, AWS, Google, etc.)
- Unified configuration for multiple API keys.
- Record type-specific validation and editing interfaces.
- DNS import/export (BIND or CSV format).
- Improved error reporting and logging.

---

## 📄 License

This project is released under the **MIT License**. See the `LICENSE` file for details.

---

## 🧑‍💻 Author

**Geoffrey Smith**  
Delphi Developer & Open Source Contributor

---

## 💬 Contributions

Contributions are welcome!  
Please follow Delphi style conventions and ensure new provider modules adhere to the shared interface design in `DNS.Base`.

---

**Delphi DNS Manager** — A cross-provider DNS management tool built with Delphi FMX.
