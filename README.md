# NMD — Network Monitoring Dashboard

**NMD** est une application desktop professionnelle de surveillance réseau et d'évaluation autorisée des vulnérabilités pour Windows, développée en **Python 3**, **PySide6 (Qt 6)**, **Nmap**, **SQLite / SQLAlchemy**, **ReportLab** et compilable sous forme de fichier exécutable autonome (`.exe`) via **PyInstaller**.

---

## 🛡️ Fonctionnalités Principales

- **Interface Graphique Moderne (PySide6)** : Theme sombre type cybersécurité, navigation latérale responsive (Dashboard, Scan, Results, Reports, Settings, About).
- **Moteur de Scan Non-Bloquant (Multithread)** : Execution asynchrone via `QThread` pour des scans réactifs sans figer l'interface.
- **Découverte Réseau & Fingerprinting** : Scan rapide (`-sn`), scan complet (`-sV -O`), pré-réglages personnalisés et classification des équipements (Router, PC, Phone, Server).
- **Évaluation des Vulnérabilités** : Exécution sécurisée des scripts Nmap NSE (`--script vuln`), extraction automatique des identifiants CVE, scores CVSS et preuves d'exécution.
- **Normalisation des Sévérités** : Classification stricte selon CVSS (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, `UNKNOWN`).
- **Base de Données SQLite / SQLAlchemy** : Stockage persistant des hôtes, de l'historique des scans et des vulnérabilités sans pertes de données.
- **Rapports Multi-Formats** :
  - Executive Assessment PDF (ReportLab)
  - Technical ASCII TXT Assessment
  - Inventory Devices PDF & CSV
  - Raw JSON Findings Data Export
- **Double Mode GUI / CLI** : Lancement automatique en interface graphique PySide6 par défaut tout en conservant la compatibilité avec les commandes CLI (`python main.py --cli`).
- **Exécutable Windows Autonome (`.exe`)** : Compilable avec PyInstaller et distribuable sur un système Windows sans Python installé.

---

## 📋 Prérequis

1. **Windows 10 / 11** (ou Linux/macOS pour le développement backend).
2. **Python 3.10+** (Compatibilité testée Python 3.12 / 3.13).
3. **Exécutable Nmap** :
   - **Windows** : Télécharger sur [nmap.org](https://nmap.org/download.html) ou via `winget install Nmap.Nmap`.
   - **Linux** : `sudo apt-get install nmap`

---

## 💻 Installation (Développement)

```bash
# 1. Créer l'environnement virtuel Python
python -m venv .venv

# 2. Activer l'environnement virtuel
# PowerShell Windows :
.\.venv\Scripts\Activate.ps1
# Bash Linux/macOS :
source .venv/bin/activate

# 3. Installer les dépendances
pip install -r requirements.txt
```

---

## 🚀 Utilisation

### Mode Interface Graphique (PySide6 Desktop App)

Pour lancer l'application graphique PySide6 :

```bash
python main.py
# ou directement
python desktop_app.py
```

### Mode Ligne de Commande (CLI)

Pour utiliser le CLI sans interface graphique :

```bash
# Scan rapide d'un sous-réseau
python main.py --cli --target 192.168.1.0/24 --scan-type quick

# Assessment de vulnérabilités avec export de rapport
python main.py --cli --target 192.168.1.10 --scan-type vulnerability --export
```

---

## 📦 Compilation de l'Exécutable Windows (.exe)

L'exécutable Windows est généré avec PyInstaller en mode `--windowed` (sans fenêtre de console noire).

### Méthode 1 : Script Batch Automatisé

```cmd
build_windows.bat
```

### Méthode 2 : Commande PyInstaller Directe

```cmd
pyinstaller --clean build_windows.spec
```

Le résultat de la compilation se trouve dans :
```text
dist/NMD/NMD-Security-Dashboard.exe
```

---

## 🛠️ Création de l'Installateur Windows (Inno Setup)

Si Inno Setup Compiler est installé sur votre système Windows :

```cmd
iscc installer_setup.iss
```

L'installateur sera généré sous :
```text
dist/NMD-Setup-v1.0.0.exe
```

---

## 🧪 Execution des Tests Unitaires

```bash
python -m pytest
```

---

## 🏗️ Architecture du Projet

```text
netwkscan/
├── src/
│   ├── core/                  # Moteur Nmap, vulnérabilités, SQLite DB, scheduler, alerte
│   │   ├── scanner.py
│   │   ├── vulnerability_scanner.py
│   │   ├── database.py
│   │   ├── analyzer.py
│   │   ├── alert_engine.py
│   │   └── scheduler.py
│   ├── gui/                   # Interface graphique PySide6 (Qt)
│   │   ├── pages/
│   │   │   ├── pyside_dashboard.py
│   │   │   ├── pyside_scan.py
│   │   │   ├── pyside_results.py
│   │   │   ├── pyside_reports.py
│   │   │   ├── pyside_settings.py
│   │   │   └── pyside_about.py
│   │   ├── theme.py
│   │   ├── workers.py
│   │   └── pyside_main_window.py
│   ├── models/                # Modèles SQLAlchemy (Device, Scan, Vulnerability)
│   ├── presets/               # Configuration des préréglages Nmap
│   ├── reports/               # Générateurs de rapports ReportLab (PDF & TXT)
│   └── utils/                 # Exporter CSV/PDF, logger audit, path resolver
├── data/                      # Base SQLite nmd.db, config.json, logs, exports
├── resources/                 # Icônes Windows (icon.ico, icon.png)
├── tests/                     # Suite de tests unitaires pytest
├── main.py                    # Point d'entrée principal (GUI / CLI)
├── desktop_app.py             # Lanceur PySide6 dédié
├── build_windows.spec         # Configuration PyInstaller
├── build_windows.bat          # Script de build automatisé Windows
├── installer_setup.iss        # Script d'installateur Inno Setup
└── .github/workflows/
    └── build-windows.yml      # GitHub Actions CI/CD Windows Latest
```

---

## ⚠️ Disclaimer & Sécurité

> [!IMPORTANT]
> **Autorisation Obligatoire** : N'effectuez des scans que sur des systèmes et réseaux dont vous êtes le propriétaire ou pour lesquels vous disposez d'une autorisation écrite formelle.
