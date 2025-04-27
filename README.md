# DATA2410 - Pålitelig Transportprotokoll (DRTP)

## Om prosjektet
Dette programmet implementerer en enkel pålitelig filoverføring over UDP, kalt **DATA2410 Reliable Transport Protocol (DRTP)**.  
Programmet kan kjøre som **server** (mottaker) eller **klient** (sender).

DRTP sikrer:
- Pålitelig levering
- In-order mottak
- Håndtering av pakketap ved hjelp av Go-Back-N (GBN)

---

## Hvordan kjøre programmet

### Krav
- Python 3 installert på maskinen
- Åpne terminal / kommandolinje i prosjektmappen

---

### Viktig
**Serveren må være startet før klienten kan koble til.**  
Hvis ikke vil klienten feile når den prøver å etablere tilkobling.

---

### Starte server

```bash
python3 application.py -s -i <ip_adresse> -p <portnummer>
