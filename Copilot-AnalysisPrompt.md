# Zentraler Copilot-Prompt für Legacy-Logon-Skripte

Nutze diese Analyseanweisung **unverändert** für alle zugehörigen Copilot-Reports, damit Ergebnisse vergleichbar bleiben.

## Ziel

Analysiere die bereitgestellten Skripte, um eine belastbare Entscheidungsgrundlage für die Ablösung veralteter Logon-Skript-Lösungen zu erstellen.
Migrationsstrategie: zuerst GPO-first, danach Intune-native. Keine Bastellösungen, keine Rücksicht auf absolute Legacy-Sonderfälle.

## Arbeitsauftrag

1. **Funktionsanalyse je Skript**
   - Was macht das Skript tatsächlich (technisch/fachlich)?
   - Welche Trigger, Inputs, Abhängigkeiten, Seiteneffekte und Zielsysteme gibt es?
2. **Nutzwert und Relevanz**
   - Ist das Skript heute noch notwendig, redundant, veraltet oder verwaist?
   - Gibt es Überschneidungen mit anderen Skripten?
3. **Risiko- und Qualitätsbewertung**
   - Sicherheitsrisiken, Stabilitätsrisiken, Wartbarkeit, Nachvollziehbarkeit.
   - Für nicht lesbare Dateien: Bewertung auf Basis Dateiname, Dateityp, Hash, Kontext und typischer Einsatzmuster.
4. **Modernisierungsoptionen ohne Legacy-Kompromisse**
   - Kurzfristig: sauberer Ersatz mit GPO-Mechanismen.
   - Mittelfristig: Intune-native Zielarchitektur.
   - Nenne explizit, was ersatzlos entfallen sollte.
5. **Entscheidungsvorlage**
   - Liefere konkrete Priorisierung mit Aufwand, Risiko, Business-Impact und empfohlener Reihenfolge.

## Ausgabeformat (verbindlich)

### A) Strukturierte Tabelle je Skript

| Skript | Zweck heute | Status (Behalten/Ersetzen/Entfernen) | Risiko | GPO-Alternative (kurzfristig) | Intune-Alternative (zielbild) | Aufwand (S/M/L) | Priorität (1-3) |
|--------|-------------|--------------------------------------|--------|-------------------------------|-------------------------------|-----------------|-----------------|

### B) Strukturierte Kerndaten (JSON-ähnlich)

```json
{
  "scripts": [
    {
      "name": "example.ps1",
      "currentPurpose": "...",
      "decision": "replace",
      "riskLevel": "high",
      "gpoTarget": "...",
      "intuneTarget": "...",
      "effort": "M",
      "priority": 1,
      "notes": "..."
    }
  ],
  "programLevelRecommendations": [
    "..."
  ]
}
```

### C) Management Summary

- Wichtigste Risiken (Top 5)
- Quick Wins (sofort umsetzbar)
- Zielbild in 3 Migrationswellen: Stabilisierung (GPO) -> Konsolidierung -> Intune-native Endstate

## Bewertungsprinzipien

- Bevorzuge Standards und supportbare Plattform-Features.
- Keine temporären Bastellösungen als Dauerlösung empfehlen.
- Legacy-only Sonderfälle dürfen kein Design-Treiber sein.
- Unsicherheiten explizit markieren und Verifikationsschritte nennen.

