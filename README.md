# DNS Trace Toolkit

Version: **1.0.0**

Dieses Repository liefert ein PowerShell-Toolkit, um den DNS-Traffic reproduzierbar zu messen und die Wirkung von DNS-Optimierungen per **Vorher/Nachher-Trace** nachzuweisen.

## Inhalt

- `dns-trace-all-in-one.ps1`  
  Führt Baseline-Trace, setzt DNS-Optimierungen, führt Optimized-Trace aus und erstellt den Vergleichsreport.
- `dns-trace-compare.ps1`  
  Vergleichsskript, wenn Baseline/Optimized als getrennte Schritte gesteuert werden sollen.

## Voraussetzungen

- Windows mit Administratorrechten für die Ausführung
- `pktmon` (in modernen Windows-Versionen enthalten)
- Optional: `tshark` für DNS-Paketzählung in `pcapng`

## Schnellstart

PowerShell als Administrator öffnen und im Repo ausführen:

```powershell
PowerShell -ExecutionPolicy Bypass -File ".\dns-trace-all-in-one.ps1"
```

Optional mit automatischem Rollback der gesetzten Policies:

```powershell
PowerShell -ExecutionPolicy Bypass -File ".\dns-trace-all-in-one.ps1" -RollbackAtEnd
```

## Ergebnisartefakte

Die Ergebnisse liegen unter:

`.\dns-trace-results\<timestamp>\`

Wichtige Dateien:

- `baseline.etl`, `optimized.etl`
- `baseline.pcapng`, `optimized.pcapng`
- `baseline.txt`, `optimized.txt`
- `summary.json`, `summary.csv` (inkl. Delta absolut/%)

## Versionierung

Semantische Versionierung:

- `MAJOR`: inkompatible Änderungen
- `MINOR`: neue, rückwärtskompatible Funktionen
- `PATCH`: Bugfixes ohne API-/Verhaltensbruch

Aktuelle Version: `v1.0.0`
