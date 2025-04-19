# 🛡️ BlackStormDOS – AI Stealth Cyber Attack Framework

[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-v1.0.0-orange)](https://github.com/burakcanbalta/blackstormdos/releases)

BlackStormDOS, yapay zeka destekli ve tam stealth özellikli gelişmiş bir DoS/DDoS saldırı framework’üdür. MAC adresi spooflama, IP sızıntı testi, WAF tespiti, decoy istekleri, HTML raporlama ve proxy rotasyonu gibi birçok siber saldırı fonksiyonunu tek bir dosyada birleştirir.

---

## 🚀 Özellikler

- 🔐 Stealth Mode: MAC/IP gizleme, WAF tespiti
- 🌐 Proxy desteği ile anonim saldırı
- 🧠 Akıllı decoy trafiği üretimi
- 📝 JSON loglama ve HTML rapor üretimi
- 🛠 Komut satırından tam kontrol
- 🧪 IP leak testi, WAF analiz motoru
- 📂 logs/ ve reports/ dizinlerinde detaylı çıktı

---

## 📦 Kurulum

```bash
pip install requests
python3 blackstormdos.py --help
```

---

## ▶️ Kullanım

```bash
python3 blackstormdos.py --target https://site.com --count 1000 --stealth --proxy proxies.txt
```

---

## 🖼️ Ekran Görüntüsü

![BlackStormDOS CLI](https://raw.githubusercontent.com/burakcanbalta/blackstormdos/main/docs/demo.png)

---

## 📁 Proje Yapısı

```
blackstormdos/
├── blackstormdos.py
├── logs/
└── reports/
```

---

## 📜 Lisans

MIT Lisansı © 2025 Burak BALTA
