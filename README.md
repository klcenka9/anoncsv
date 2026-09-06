# anoncsv

Malý open-source CLI nástroj pro anonymizaci citlivých hodnot v CSV souborech.
Data se zpracovávají pouze lokálně a původní vstupní soubor se nikdy nepřepisuje.

## Požadavky

- Python 3.10 nebo novější

Instalace CLI z projektu:

```bash
python -m pip install .
anoncsv data.csv anonymized.csv --salt muj-tajny-salt
```

## Použití

```bash
python anoncsv.py data.csv anonymized.csv --salt muj-tajny-salt
```

Nástroj automaticky rozpozná sloupce podle názvu nebo obsahu. Aktuálně podporuje:

- `email`: převede adresu na anonymní doménu `.invalid`
- `phone`: vygeneruje telefonní číslo stejné délky
- `ip`: použije dokumentační rozsah `198.51.100.0/24` nebo `2001:db8::/32`
- `name`: vytvoří anonymní stabilní identifikátor osoby
- `token`: vytvoří stabilní jednosměrný token pro vlastní hodnoty

Typ sloupce lze zadat ručně. Ruční nastavení má přednost před automatickou detekcí:

```bash
python anoncsv.py users.csv users-anonymized.csv \
  --map customer_id=token \
  --map full_name=name \
  --map email=email \
  --salt projekt-2026
```

Pro CSV oddělené středníkem použijte `--delimiter ';'`.

JSON soubory ve formátu seznamu objektů lze zpracovat stejně:

```bash
python anoncsv.py data.json anonymized.json --salt muj-tajny-salt
```

Excel soubory lze zpracovat po instalaci volitelné závislosti:

```bash
python -m pip install 'anoncsv[excel]'
python anoncsv.py data.xlsx anonymized.xlsx --salt muj-tajny-salt
```

TSV je podporováno přes `--delimiter '\t'`. Webové rozhraní zatím přijímá CSV.

## Konzistence tokenů

Stejný `--salt` vytvoří pro stejnou hodnotu stejný anonymní výsledek, takže lze
spojovat více anonymizovaných exportů. Salt zacházejte jako s tajným údajem:
bez něj nelze výsledky zpětně propojit mezi běhy. Nástroj neumožňuje obnovit
původní hodnoty.

## Testy

```bash
python -m pytest -q
```

## Webové rozhraní

```bash
python webapp.py
```

Poté otevřete [http://127.0.0.1:8000](http://127.0.0.1:8000). CSV můžete vložit
do textového pole nebo vybrat přes file picker. Po zpracování se výsledek zobrazí
v náhledu a lze ho stáhnout. Server naslouchá jen na lokální adrese, takže data
nejsou vystavena do sítě. Webový požadavek má limit 5 MB a výsledky se ukládají
jen do dočasné paměti serveru.

Projekt je první vydání `v0.1.0`. Před použitím v produkci je vhodné doplnit
kontrolu unikátnosti náhradních hodnot, šifrované mapování a auditní report.
