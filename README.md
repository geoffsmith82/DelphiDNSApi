# Delphi DNS API Library, Demonstration App & ACME Certificate Client

A comprehensive **Delphi FMX application** and **DNS API library** designed for managing DNS zones/records across multiple cloud providers.
Now extended with a full **ACME Certificate Client** supporting **DNS-01 authentication**, enabling automated SSL/TLS certificate issuance similar to Certbot — but in native Delphi.

This project now includes:

* A modular **DNS provider system**
* A cross-platform **FMX DNS Manager UI**
* A new **ACME certificate module** with:

  * ACME Account registration
  * Order creation, authorization tracking
  * DNS-01 challenge handling
  * Certificate finalisation and chain splitting
  * Automatic certificate storage (Windows/Linux compatible)

---

## 🚀 Features

### DNS Management

* **Manage DNS zones** from supported providers.
* **Create and delete zones** via the UI.
* **Add, edit, delete DNS records** using provider APIs.
* **Secure credential storage** for provider API keys.
* **Consistent interface** across all DNS providers.
* **FMX UI with animated panels & responsive layouts**.

### 🔐 ACME Certificate Client (New!)

* Fully implemented **ACME v2 client** (Let’s Encrypt / Buypass / ZeroSSL compatible).
* Uses **DNS-01 validation** via your selected DNS provider.
* Native Delphi implementation of:

  * JWK account key
  * JWS-signed ACME requests
  * Nonces, directory discovery, account registration
  * Order lifecycle management
  * Authorization + DNS challenge preparation
  * Finalization and certificate retrieval
* **Automatic certificate storage**, structured like Certbot:

  * `/etc/letsencrypt/live/<domain>` on Linux
  * `%ProgramData%\Acme\<domain>` on Windows
* Built-in certificate chain splitting (`cert.pem`, `chain.pem`, `fullchain.pem`)
* Cross-platform support (Windows, Linux, macOS)

---

## ⚙️ Requirements

* **Delphi 11+ (FMX Framework)**
* DNS provider API credentials (e.g., Vultr, DigitalOcean)
* Internet access for DNS and ACME API calls
* Domain name that you control (for ACME validation)

---

## 🧠 Architecture

### DNS API Layer

* Reusable **provider-neutral abstraction** in `DNS.Base`.
* Provider modules implement zone/record CRUD via a shared class structure.
* Asynchronous operations using `TTask` & `Synchronize`.

### ACME Certificate System (New)

* Located in `ACME.Client.*` units.
* Modular design:

  * `TACMEClient` — high-level API

* Integrates with **any DNS provider** that supports TXT record management.

---

## 🔧 Setup Instructions

### DNS Manager

1. Open the project in **Delphi 11+**.
2. Enter the API key for your DNS provider.
3. Manage DNS zones and records through the UI.

### ACME Certificate Client (DNS-01)

1. Create an ACME account (staging or production).
2. Start a new certificate order.
3. The client automatically:

   * Generates DNS-01 TXT record content
   * Publishes it using your selected DNS provider
   * Waits for propagation
   * Notifies the ACME server
4. Upon successful validation:

   * Certificates are finalized
   * Stored in a Certbot-compatible folder structure
   * Returned to the application for further processing

---

## 🧩 Multi-Provider Support (DNS + ACME)

This project now supports DNS + ACME DNS-01 workflows for the following providers:

| Provider                | DNS Support | ACME-DNS Ready               |
| ----------------------- | ----------- | ---------------------------- |
| **Vultr DNS**           | ✅           | ✅                            |
| **DigitalOcean DNS**    | ✅           | ✅                            |
| **Microsoft Azure DNS** | ✅           | ⚠️ (propagation can be slow) |
| **Bunny.net**           | ⏳ Untested  | ⏳                            |
| **Cloudflare DNS**      | ⏳ Untested  | ⏳                            |
| **AWS Route53**         | ⏳ Untested  | ⏳                            |
| **Google Cloud DNS**    | ⏳ Untested  | ⏳                            |
| **GoDaddy**             | Planned     | Planned                      |
| **Namecheap**           | Planned     | Planned                      |
| **BinaryLane (AU)**     | Planned     | Planned                      |
| **PowerDNS**            | Planned     | Planned                      |
| **OpenStack Designate** | Planned     | Planned                      |

---

## 📂 Certificate Storage Layout (New)

Matches Certbot conventions for maximum compatibility.

### Linux

```
/etc/letsencrypt/live/<domain>/cert.pem
/etc/letsencrypt/live/<domain>/chain.pem
/etc/letsencrypt/live/<domain>/fullchain.pem
/etc/letsencrypt/live/<domain>/privkey.pem
```

### Windows

```
%ProgramData%\Acme\<domain>\cert.pem
%ProgramData%\Acme\<domain>\chain.pem
%ProgramData%\Acme\<domain>\fullchain.pem
%ProgramData%\Acme\<domain>\privkey.pem
```

---

## 📦 File Overview (Updated)

| File                                                     | Description                                           |
| -------------------------------------------------------- | ----------------------------------------------------- |
| `DNS.UI.Main.pas/.fmx`                                   | Core FMX interface for provider + ACME functions.     |
| `DNS.Base.pas`                                           | Shared provider abstractions.                         |
| `DNS.Vultr.pas`, `DNS.DigitalOcean.pas`, `DNS.Azure.pas` | Provider-specific DNS implementations.                |
| `DNS.Helpers.pas`                                        | JSON & REST utilities.                                |
| `ACME.Client.pas`                                        | High-level ACME workflow controller.                  |
| `ACME.Order.pas`                                         | ACME order creation, challenge polling, finalization. |
| `ACME.Client.Dns01.pas`                                  | Dns-01 validation logic.                              |
| `ACME.Client.Http01.pas`                                 | Http-01 validation logic. Mostly TODO:                |
| `ACME.TaurusCrypto.pas`                                  | Certificate/Encryption handling code                  |


---

## 🧪 Planned Future Enhancements

* UI for scheduled auto-renewal of certificates.
* Background service (Windows/Linux daemon) for unattended renewal.
* Additional DNS providers.
* OCSP stapling helper.
* Import/export DNS zone editor.
* Advanced logging.

---

## 📄 License

Released under the **MIT License**.

---

## 🧑‍💻 Author

**Geoffrey Smith**
Delphi Developer & Open Source Contributor

---

## 💬 Contributions

Contributions are welcome!
Please follow Delphi style conventions and ensure new modules conform to the shared interfaces.


