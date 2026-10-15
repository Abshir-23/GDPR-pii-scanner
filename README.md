# GDPR PII-skanner

Et automatiseringsverktøy som skanner filer og mapper etter personopplysninger (PII) og rapporterer hvor de ligger. Det svarer på spørsmålet ethvert GDPR-arbeid må besvare først: **hvor ligger personopplysningene våre, og hva slags opplysninger er det?**

Å finne ut av dette for hånd skalerer ikke. Verktøyet gjør det automatisk, så det kan kjøres etter en fast plan eller inne i en CI-pipeline.

## Hvorfor dette er viktig for GDPR

- **Kartlegging av data** – du kan ikke beskytte eller slette personopplysninger du ikke vet at du har. Dette er grunnlaget for en **protokoll over behandlingsaktiviteter (artikkel 30)**.
- **Dataminimering (artikkel 5)** – når PII dukker opp i logger, eksporter og midlertidige filer, ser du hvor data blir lagret som sannsynligvis ikke burde vært det.
- **Beredskap ved brudd** – når du vet hvilke filer som inneholder fødselsnumre eller kortnumre, vet du hvor alvorlig en lekkasje er.

## Hva den finner

| Type | Hvordan falske treff unngås |
|------|-------------------------------|
| E-postadresser | Standard mønster |
| Norske fødselsnumre | Validert med de offisielle kontrollsifrene (mod 11) |
| Betalingskortnumre | Validert med Luhn-algoritmen |
| Telefonnumre (norske) | Nøyaktig 8 siffer, ikke del av et lengre tall |
| IPv4-adresser | Hver oktett sjekkes mot gyldig område |

Validering er viktig: et tall med 11 siffer rapporteres bare som fødselsnummer hvis kontrollsifrene stemmer, og et kortnummer bare hvis det består Luhn-sjekken. Det gjør rapporten pålitelig i stedet for full av støy.

## Innebygd personvern

Rapporten **maskerer hver verdi den finner** (`*********59`), slik at resultatet ikke selv blir en ny haug med personopplysninger. Et verktøy som skal hjelpe med GDPR, bør ikke lekke PII i sine egne logger.

## Bruk

Ingen avhengigheter må installeres for å kjøre det, det bruker bare Pythons standardbibliotek.

```bash
# Skann en mappe
python -m gdpr_scanner sample_data/

# Maskinlesbar utskrift
python -m gdpr_scanner sample_data/ --format json > report.json

# La bygget feile hvis det finnes PII (for CI-pipelines)
python -m gdpr_scanner ./exports --fail-on-findings
```

### Eksempel på utskrift

```
============================================================
GDPR PII-SKANNERAPPORT
============================================================
Filer skannet      : 3
Filer hoppet over  : 0 (ikke tekst)
Filer med PII      : 2
Totalt antall funn : 13

Funn per type:
  E-postadresser                             5
  Telefonnumre                               4
  Norske fødselsnumre                        2
  Betalingskortnumre                         1
  IP-adresser                                1
```

## Automatisering

Siden verktøyet avslutter med kode `1` når det finner PII, kan det settes rett inn i en pipeline. Eksempel på et steg i GitHub Actions som stopper en commit som legger personopplysninger inn i filer som spores:

```yaml
- name: GDPR PII-skanning
  run: python -m gdpr_scanner . --fail-on-findings
```

Den samme kommandoen kan kjøres som en planlagt jobb som skanner delte mapper på nytt over tid.

## Prosjektstruktur

```
gdpr_scanner/
  detectors.py   # regex-mønstre + validering av fødselsnummer og Luhn, med maskering av verdier
  scanner.py     # går gjennom filer, skanner linje for linje og samler resultatene
  report.py      # rapporter til konsoll og JSON
  cli.py         # kommandolinjegrensesnitt
sample_data/     # falske data å teste på (ingen ekte personer)
tests/           # 14 tester for detektorene og skanneren
```

## Tester

```bash
pytest -q
```

Dekker hver detektor, validering av kontrollsifre (et feil fødselsnummer eller kortnummer blir **ikke** flagget), maskering av verdier og en full skanning av eksempelmappen.

## Merknader

- Alle data i `sample_data/` er syntetiske. Fødselsnumrene har gyldige kontrollsifre, men tilhører ikke ekte personer, og kortnummeret er Visas standard testnummer.
- Deteksjonen er basert på mønstre, så den finner strukturerte identifikatorer godt. Navn og adresser i fritekst ville krevd språkteknologi (NLP), som er et naturlig neste steg.

## Teknologi

Python (bare standardbiblioteket) · pytest
