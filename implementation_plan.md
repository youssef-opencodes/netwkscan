# Analyse Complète du Projet et Plan de Résolution

Cette analyse détaillée met en évidence les failles architecturales, les problèmes de concurrence (threads), les risques de fuites de ressources, ainsi que les pistes d'amélioration du code.

## User Review Required

> [!WARNING]
> Le code souffre actuellement d'un problème majeur concernant la fermeture des threads et des sous-processus. La fermeture de la fenêtre principale pendant un scan actif provoquera un plantage et potentiellement des processus "zombies".

## Open Questions

1. **Interface Graphique obsolète** : Le projet contient un fichier `main_window.py` (basé sur CustomTkinter) ainsi qu'un fichier `pyside_main_window.py` (basé sur PySide6). Confirmez-vous que la version CustomTkinter est obsolète et peut être supprimée pour éviter la confusion ?
2. **Processus Nmap (Zombies)** : Lors de la fermeture brutale, préférez-vous que les scans en cours soient terminés de force (tués), ou que l'application bloque la fermeture pendant quelques secondes pour s'arrêter proprement ?

---

## Problèmes Identifiés (Analyse du Code)

### 1. Cycle de vie des QThreads et Fermeture Abrupte (Crash)
- **Fichier** : `src/gui/pyside_main_window.py`
- **Problème** : L'événement `closeEvent` stoppe le `NetworkScheduler` (qui est un thread Python classique) mais ignore totalement les `QThread` en cours d'exécution dans `ScanPage` et `ReportsPage` (`ScanWorker`, `VulnerabilityScanWorker`, `ExportWorker`). Lorsque la fenêtre est détruite, Qt supprime l'arbre d'objets, ce qui détruit violemment les wrappers Python des threads C++ encore actifs.
- **Résultat** : Erreur `QThread: Destroyed while thread is still running` et crash de l'application (Segfault).

### 2. Fuite de Sous-processus (Nmap Zombies)
- **Fichier** : `src/core/scanner.py` & `src/gui/workers.py`
- **Problème** : Les scans Nmap sont lancés via `subprocess.Popen`. Si l'application se ferme ou si le QThread est détruit brutalement, le processus `nmap.exe` enfant n'est pas terminé (il devient orphelin / "zombie").
- **Résultat** : Accumulation de processus `nmap` invisibles en arrière-plan qui consomment 100% du CPU.

### 3. Conditions de course (Race Condition) sur la Configuration
- **Fichier** : `src/core/scheduler.py` (lignes 111-115)
- **Problème** : Le thread d'arrière-plan du planificateur modifie le fichier de configuration JSON en appelant `save_config(cfg)` pendant l'auto-détection. Si l'utilisateur modifie les paramètres dans `SettingsPage` exactement au même moment (dans le thread UI principal), le fichier de configuration peut être corrompu.

### 4. Code Mort (Dead Code) et Dette Technique
- **Fichier** : `src/gui/main_window.py`
- **Problème** : Ce fichier contient une ancienne implémentation d'interface utilisateur utilisant `CustomTkinter`. Le lanceur officiel actuel (`desktop_app.py`) utilise `PySide6`. La présence de deux frameworks graphiques augmente considérablement la complexité du code.

---

## Plan d'Implémentation Proposé (Corrections)

### 1. Sécurisation de la fermeture des Threads et Sous-processus
Pour éviter le crash et les processus orphelins :

#### [MODIFY] `src/gui/pyside_main_window.py`
- Ajouter une référence ou un moyen d'accéder aux pages enfants (notamment `ScanPage` et `ReportsPage`).
- Surcharger le `closeEvent` pour :
  1. Demander poliment l'arrêt des scans (`self.page_scan.stop_scan()`).
  2. Demander l'arrêt des exports actifs dans `ReportsPage`.
  3. Attendre au maximum 2-3 secondes que les threads terminent proprement leur exécution.

#### [MODIFY] `src/gui/pages/pyside_reports.py`
- Ajouter une méthode `stop_all_exports()` qui itère sur `self._active_workers` et appelle `worker.wait()` pour forcer l'arrêt propre avant la fermeture.

### 2. Gestion stricte du sous-processus Nmap
#### [MODIFY] `src/core/scanner.py`
- Modifier `cancel_scan()` pour s'assurer que le signal `.terminate()` puis `.kill()` est bien envoyé au sous-processus si celui-ci ne répond pas.

### 3. Résolution de la condition de course (Race Condition)
#### [MODIFY] `src/core/scheduler.py`
- Utiliser un mécanisme de verrouillage (Lock) lors de l'appel à `save_config` (si le gestionnaire de configuration ne le fait pas déjà), ou déléguer la mise à jour de la configuration de l'auto-détection au thread principal (GUI) plutôt qu'au thread en arrière-plan.

### 4. Nettoyage de la dette technique
#### [DELETE] `src/gui/main_window.py`
- Suppression du fichier s'il est validé comme étant obsolète (CustomTkinter).

## Verification Plan

### Automated Tests
- Il n'y a pas de suite de tests unitaires visible pour l'interface graphique.

### Manual Verification
1. **Fermeture sécurisée** : Lancer un scan Nmap (très long) ou un export complexe, puis fermer immédiatement l'application avec la croix (X).
   - **Attente** : L'application doit intercepter la fermeture, tuer `nmap`, attendre la fin du `QThread`, puis se fermer sans erreur dans la console (pas de `QThread: Destroyed...`).
2. **Vérification des processus** : Ouvrir le gestionnaire des tâches Windows (Task Manager), lancer un scan, fermer l'application, et s'assurer qu'aucun processus `nmap.exe` ou `python.exe` résiduel ne subsiste.
