# securejson

[![Go Reference](https://pkg.go.dev/badge/github.com/yourusername/securejson.svg)](https://pkg.go.dev/github.com/yourusername/securejson)
[![Go Report Card](https://goreportcard.com/badge/github.com/yourusername/securejson)](https://goreportcard.com/report/github.com/yourusername/securejson)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A **security-hardened**, **production-ready** JSON serialization and deserialization library for Go. Built with defense-in-depth principles to mitigate OWASP Top 10 risks while maintaining drop-in compatibility with `encoding/json`.

---

## 🔐 Security-First Design

| Layer | Protection | OWASP Mapping |
|-------|-----------|---------------|
| **Pre-parse** | Input sanitization, schema validation | A04: Insecure Design |
| **Parse** | Depth limits, size limits, strict mode, context cancellation | A03: Injection, A04: Insecure Design |
| **Post-parse** | Struct tag validation (`validate:"required,email"`) | A01: Broken Access Control, A07: Auth Failures |
| **Output** | HTML escaping, buffer pooling, no panic propagation | A03: XSS, A09: Logging Failures |

---
