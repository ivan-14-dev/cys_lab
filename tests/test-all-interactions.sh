#!/usr/bin/env bash
# Full interaction test for all CYS_LAB services
set -eo pipefail
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'; BOLD='\033[1m'
PASS=0; FAIL=0; TOTAL=0

check() {
  TOTAL=$((TOTAL+1))
  local desc="$1"; local expected="$2"; local actual="$3"
  if echo "$actual" | grep -qiF "$expected"; then
    echo -e "  ${GREEN}✓${NC} $desc"
    PASS=$((PASS+1))
  else
    echo -e "  ${RED}✗${NC} $desc (attendu: '$expected')"
    echo -e "    → reçu: $(echo "$actual" | head -c 200)"
    FAIL=$((FAIL+1))
  fi
}

check_status() {
  TOTAL=$((TOTAL+1))
  local desc="$1"; local expected="$2"; local actual="$3"
  if [[ "$actual" == "$expected" ]]; then
    echo -e "  ${GREEN}✓${NC} $desc [HTTP $actual]"
    PASS=$((PASS+1))
  else
    echo -e "  ${RED}✗${NC} $desc (attendu HTTP $expected, reçu HTTP $actual)"
    FAIL=$((FAIL+1))
  fi
}

api() {
  curl -s -w '\n%{http_code}' "$@" 2>/dev/null
}

extract_body() { echo "$1" | sed '$d'; }
extract_code() { echo "$1" | tail -1; }

echo -e "\n${BOLD}═══════════════════════════════════════════════${NC}"
echo -e "${BOLD}  TEST COMPLET — INTERACTIONS UTILISATEUR CYS_LAB${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════${NC}\n"

# ─────────────────────────────────────────────
echo -e "${BOLD}🔓 1. SQL INJECTION — VULNÉRABLE (port 5021)${NC}"
# ─────────────────────────────────────────────
# Page d'accueil
R=$(api http://127.0.0.1:5021/); check_status "Page d'accueil charge" "200" "$(extract_code "$R")"
check "Contient le formulaire HTML" "username" "$(extract_body "$R")"

# Bouton: Login normal (alice)
R=$(api -X POST http://127.0.0.1:5021/api/login -H 'Content-Type: application/json' -d '{"username":"alice","password":"lab_alice_pass"}')
check_status "Login alice → 200" "200" "$(extract_code "$R")"
check "Login alice → authenticated" "authenticated" "$(extract_body "$R")"

# Bouton: Login mauvais mdp
R=$(api -X POST http://127.0.0.1:5021/api/login -H 'Content-Type: application/json' -d '{"username":"alice","password":"wrong"}')
check_status "Mauvais mdp → 401" "401" "$(extract_code "$R")"

# Bouton payload: Tautologie ' OR '1'='1
R=$(api -X POST http://127.0.0.1:5021/api/login -H 'Content-Type: application/json' -d '{"username":"admin","password":"'\'' OR '\''1'\''='\''1"}')
check_status "Tautologie bypass → 200" "200" "$(extract_code "$R")"
check "Tautologie → authentifié" "authenticated" "$(extract_body "$R")"

# Bouton payload: Comment admin'--
R=$(api -X POST http://127.0.0.1:5021/api/login -H 'Content-Type: application/json' -d '{"username":"admin'\''--","password":"x"}')
check_status "Comment bypass → 200" "200" "$(extract_code "$R")"

# Bouton payload: UNION injection
R=$(api -X POST http://127.0.0.1:5021/api/login -H 'Content-Type: application/json' -d "{\"username\":\"' UNION SELECT 1,'injected','data','admin'--\",\"password\":\"x\"}")
check_status "UNION injection → 200" "200" "$(extract_code "$R")"
check "UNION → user 'injected'" "injected" "$(extract_body "$R")"

# ─────────────────────────────────────────────
echo -e "\n${BOLD}🔒 2. SQL INJECTION — SÉCURISÉ (port 5022)${NC}"
# ─────────────────────────────────────────────
R=$(api http://127.0.0.1:5022/); check_status "Page d'accueil charge" "200" "$(extract_code "$R")"

R=$(api -X POST http://127.0.0.1:5022/api/login -H 'Content-Type: application/json' -d '{"username":"alice","password":"lab_alice_pass"}')
check_status "Login alice → 200" "200" "$(extract_code "$R")"
check "Login alice → authenticated" "authenticated" "$(extract_body "$R")"

R=$(api -X POST http://127.0.0.1:5022/api/login -H 'Content-Type: application/json' -d '{"username":"admin","password":"'\'' OR '\''1'\''='\''1"}')
check_status "Tautologie bloquée → 401" "401" "$(extract_code "$R")"

R=$(api -X POST http://127.0.0.1:5022/api/login -H 'Content-Type: application/json' -d '{"username":"admin'\''--","password":"x"}')
check_status "Comment bloqué → 401" "401" "$(extract_code "$R")"

R=$(api -X POST http://127.0.0.1:5022/api/login -H 'Content-Type: application/json' -d "{\"username\":\"' UNION SELECT 1,'injected','data','admin'--\",\"password\":\"x\"}")
check_status "UNION bloqué → 401" "401" "$(extract_code "$R")"

# ─────────────────────────────────────────────
echo -e "\n${BOLD}🔓 3. COMMAND INJECTION — VULNÉRABLE (port 5003)${NC}"
# ─────────────────────────────────────────────
R=$(api http://127.0.0.1:5003/); check_status "Page d'accueil charge" "200" "$(extract_code "$R")"

# Bouton: Ping normal
R=$(api -X POST http://127.0.0.1:5003/api/ping -H 'Content-Type: application/json' -d '{"target":"127.0.0.1"}')
check_status "Ping normal → 200" "200" "$(extract_code "$R")"
check "Ping → contient output" "output" "$(extract_body "$R")"

# Bouton payload: ; echo INJECTED
R=$(api -X POST http://127.0.0.1:5003/api/ping -H 'Content-Type: application/json' -d '{"target":"127.0.0.1; echo INJECTION_PROOF"}')
check_status "Injection shell → 200" "200" "$(extract_code "$R")"
check "Injection exécutée" "INJECTION_PROOF" "$(extract_body "$R")"

# Bouton payload: $(id)
R=$(api -X POST http://127.0.0.1:5003/api/ping -H 'Content-Type: application/json' -d '{"target":"$(echo CMD_SUB_TEST)"}')
check_status "Cmd substitution → 200" "200" "$(extract_code "$R")"



# ─────────────────────────────────────────────
echo -e "\n${BOLD}🔒 4. COMMAND INJECTION — SÉCURISÉ (port 5004)${NC}"
# ─────────────────────────────────────────────
R=$(api http://127.0.0.1:5004/); check_status "Page d'accueil charge" "200" "$(extract_code "$R")"

R=$(api -X POST http://127.0.0.1:5004/api/ping -H 'Content-Type: application/json' -d '{"target":"127.0.0.1"}')
check_status "Ping 127.0.0.1 → 200" "200" "$(extract_code "$R")"
check "Pas bloqué" "false" "$(extract_body "$R")"

R=$(api -X POST http://127.0.0.1:5004/api/ping -H 'Content-Type: application/json' -d '{"target":"127.0.0.1; echo INJECTED"}')
check_status "Injection bloquée → 400" "400" "$(extract_code "$R")"
check "Bloqué=true" "blocked" "$(extract_body "$R")"

R=$(api -X POST http://127.0.0.1:5004/api/ping -H 'Content-Type: application/json' -d '{"target":"8.8.8.8"}')
check_status "IP externe bloquée → 400" "400" "$(extract_code "$R")"

R=$(api -X POST http://127.0.0.1:5004/api/ping -H 'Content-Type: application/json' -d '{"target":""}')
check_status "Target vide bloquée → 400" "400" "$(extract_code "$R")"

R=$(api -X POST http://127.0.0.1:5004/api/ping -H 'Content-Type: application/json' -d '{"target":"$(id)"}')
check_status 'Cmd $(id) bloqué → 400' "400" "$(extract_code "$R")"

# ─────────────────────────────────────────────
echo -e "\n${BOLD}🔓 5. XSS — VULNÉRABLE (port 5001)${NC}"
# ─────────────────────────────────────────────
R=$(api http://127.0.0.1:5001/); check_status "Page d'accueil charge" "200" "$(extract_code "$R")"

api http://127.0.0.1:5001/clear > /dev/null

# Bouton: Poster commentaire normal
R=$(api -X POST http://127.0.0.1:5001/api/comment -H 'Content-Type: application/json' -d '{"name":"TestUser","comment":"Bonjour!"}')
check_status "Commentaire normal → 200" "200" "$(extract_code "$R")"
check "Status ok" "ok" "$(extract_body "$R")"

# Bouton payload: <script>
R=$(api -X POST http://127.0.0.1:5001/api/comment -H 'Content-Type: application/json' -d '{"name":"Hacker","comment":"<script>alert(1)</script>"}')
check_status "XSS payload stocké → 200" "200" "$(extract_code "$R")"

# Vérifier qu'il est stocké brut
R=$(api http://127.0.0.1:5001/api/last)
check "Script stocké brut" "<script>" "$(extract_body "$R")"

# Bouton payload: <img onerror>
R=$(api -X POST http://127.0.0.1:5001/api/comment -H 'Content-Type: application/json' -d '{"name":"Hacker2","comment":"<img src=x onerror=alert(1)>"}')
check_status "img payload stocké → 200" "200" "$(extract_code "$R")"

# Lister commentaires
R=$(api http://127.0.0.1:5001/api/comments)
check_status "Lister commentaires → 200" "200" "$(extract_code "$R")"
check "3 commentaires stockés" "Hacker2" "$(extract_body "$R")"

# Bouton: Clear
R=$(api http://127.0.0.1:5001/clear)
check "Clear fonctionne" "ok" "$(extract_body "$R")"

# ─────────────────────────────────────────────
echo -e "\n${BOLD}🔒 6. XSS — SÉCURISÉ (port 5002)${NC}"
# ─────────────────────────────────────────────
R=$(api http://127.0.0.1:5002/); check_status "Page d'accueil charge" "200" "$(extract_code "$R")"

api http://127.0.0.1:5002/clear > /dev/null

R=$(api -X POST http://127.0.0.1:5002/api/comment -H 'Content-Type: application/json' -d '{"name":"TestUser","comment":"Bonjour!"}')
check_status "Commentaire normal → 200" "200" "$(extract_code "$R")"

R=$(api -X POST http://127.0.0.1:5002/api/comment -H 'Content-Type: application/json' -d '{"name":"<script>alert(1)</script>","comment":"test"}')
check_status "XSS dans nom → 400" "400" "$(extract_code "$R")"
check "Caractères invalides détectés" "invalide" "$(extract_body "$R")"

R=$(api -X POST http://127.0.0.1:5002/api/comment -H 'Content-Type: application/json' -d '{"name":"","comment":"test"}')
check_status "Nom vide → 400" "400" "$(extract_code "$R")"

R=$(api -X POST http://127.0.0.1:5002/api/comment -H 'Content-Type: application/json' -d '{"name":"ok","comment":""}')
check_status "Commentaire vide → 400" "400" "$(extract_code "$R")"

# Vérifier headers sécurité
HEADERS=$(curl -sI http://127.0.0.1:5002/)
check "CSP header présent" "Content-Security-Policy" "$HEADERS"
check "X-Frame-Options présent" "X-Frame-Options" "$HEADERS"
check "X-Content-Type-Options présent" "X-Content-Type-Options" "$HEADERS"

api http://127.0.0.1:5002/clear > /dev/null

# ─────────────────────────────────────────────
echo -e "\n${BOLD}🔓 7. SSTI — VULNÉRABLE (port 5005)${NC}"
# ─────────────────────────────────────────────
R=$(api http://127.0.0.1:5005/); check_status "Page d'accueil charge" "200" "$(extract_code "$R")"

# Bouton: Nom normal
R=$(api "http://127.0.0.1:5005/api/greet?name=Alice")
check_status "Greet Alice → 200" "200" "$(extract_code "$R")"
check "Output = Hello Alice!" "Hello Alice!" "$(extract_body "$R")"

# Bouton payload: {{7*7}}
R=$(api "http://127.0.0.1:5005/api/greet?name=%7B%7B7*7%7D%7D")
check_status "{{7*7}} → 200" "200" "$(extract_code "$R")"
check "Template évalué → 49" "49" "$(extract_body "$R")"

# Bouton payload: {{config}}
R=$(api "http://127.0.0.1:5005/api/greet?name=%7B%7Bconfig%7D%7D")
check_status "{{config}} → 200" "200" "$(extract_code "$R")"
check "Config rendu (vide ou leak)" "Hello" "$(extract_body "$R")"

# Nom par défaut
R=$(api "http://127.0.0.1:5005/api/greet")
check "Défaut = Hello World!" "Hello World!" "$(extract_body "$R")"

# ─────────────────────────────────────────────
echo -e "\n${BOLD}🔒 8. SSTI — SÉCURISÉ (port 5006)${NC}"
# ─────────────────────────────────────────────
R=$(api http://127.0.0.1:5006/); check_status "Page d'accueil charge" "200" "$(extract_code "$R")"

R=$(api "http://127.0.0.1:5006/api/greet?name=Alice")
check_status "Greet Alice → 200" "200" "$(extract_code "$R")"
check "Output = Hello Alice!" "Hello Alice!" "$(extract_body "$R")"

R=$(api "http://127.0.0.1:5006/api/greet?name=%7B%7B7*7%7D%7D")
check_status "{{7*7}} bloqué → 400" "400" "$(extract_code "$R")"
check "Bloqué flag" "blocked" "$(extract_body "$R")"

R=$(api "http://127.0.0.1:5006/api/greet")
check "Défaut = Hello World!" "Hello World!" "$(extract_body "$R")"

# ─────────────────────────────────────────────
echo -e "\n${BOLD}🔓 9. NoSQL INJECTION — VULNÉRABLE (port 5007)${NC}"
# ─────────────────────────────────────────────
R=$(api http://127.0.0.1:5007/); check_status "Page d'accueil charge" "200" "$(extract_code "$R")"

R=$(api -X POST http://127.0.0.1:5007/api/login -H 'Content-Type: application/json' -d '{"username":"alice","password":"lab_alice_pass"}')
check_status "Login alice → 200" "200" "$(extract_code "$R")"
check "Authentifié" "authenticated" "$(extract_body "$R")"

# Bouton payload: $ne
R=$(api -X POST http://127.0.0.1:5007/api/login -H 'Content-Type: application/json' -d '{"username":"admin","password":{"$ne":null}}')
check_status 'NoSQL $ne bypass → 200' "200" "$(extract_code "$R")"
check 'NoSQL $ne → admin authentifié' "admin" "$(extract_body "$R")"

# Bouton payload: $gt
R=$(api -X POST http://127.0.0.1:5007/api/login -H 'Content-Type: application/json' -d '{"username":"admin","password":{"$gt":""}}')
check_status 'NoSQL $gt bypass → 200' "200" "$(extract_code "$R")"

# Mauvais mot de passe
R=$(api -X POST http://127.0.0.1:5007/api/login -H 'Content-Type: application/json' -d '{"username":"alice","password":"wrong"}')
check_status "Mauvais mdp → 401" "401" "$(extract_code "$R")"

# ─────────────────────────────────────────────
echo -e "\n${BOLD}🔒 10. NoSQL INJECTION — SÉCURISÉ (port 5008)${NC}"
# ─────────────────────────────────────────────
R=$(api http://127.0.0.1:5008/); check_status "Page d'accueil charge" "200" "$(extract_code "$R")"

R=$(api -X POST http://127.0.0.1:5008/api/login -H 'Content-Type: application/json' -d '{"username":"alice","password":"lab_alice_pass"}')
check_status "Login alice → 200" "200" "$(extract_code "$R")"

R=$(api -X POST http://127.0.0.1:5008/api/login -H 'Content-Type: application/json' -d '{"username":"admin","password":{"$ne":null}}')
check_status 'NoSQL $ne bloqué → 400' "400" "$(extract_code "$R")"
check "Bloqué flag" "blocked" "$(extract_body "$R")"

R=$(api -X POST http://127.0.0.1:5008/api/login -H 'Content-Type: application/json' -d '{"username":"admin","password":{"$gt":""}}')
check_status 'NoSQL $gt bloqué → 400' "400" "$(extract_code "$R")"

# ─────────────────────────────────────────────
echo -e "\n${BOLD}🔓 11. LDAP INJECTION — VULNÉRABLE (port 5009)${NC}"
# ─────────────────────────────────────────────
R=$(api http://127.0.0.1:5009/); check_status "Page d'accueil charge" "200" "$(extract_code "$R")"

# Bouton: Recherche normale
R=$(api "http://127.0.0.1:5009/api/search?username=ivan")
check_status "Recherche ivan → 200" "200" "$(extract_code "$R")"
check "Trouvé ivan" "ivan" "$(extract_body "$R")"

# Bouton payload: * (wildcard)
R=$(api "http://127.0.0.1:5009/api/search?username=*")
check_status "Wildcard * → 200" "200" "$(extract_code "$R")"
check "Retourne tous les users (3)" 'count' "$(extract_body "$R")"

# Bouton payload: *)(uid=*)
R=$(api "http://127.0.0.1:5009/api/search?username=*)(uid=*)")
check_status "Injection LDAP → 200" "200" "$(extract_code "$R")"

# ─────────────────────────────────────────────
echo -e "\n${BOLD}🔒 12. LDAP INJECTION — SÉCURISÉ (port 5010)${NC}"
# ─────────────────────────────────────────────
R=$(api http://127.0.0.1:5010/); check_status "Page d'accueil charge" "200" "$(extract_code "$R")"

R=$(api "http://127.0.0.1:5010/api/search?username=ivan")
check_status "Recherche ivan → 200" "200" "$(extract_code "$R")"
check "Trouvé ivan" "ivan" "$(extract_body "$R")"

R=$(api "http://127.0.0.1:5010/api/search?username=*")
check_status "Wildcard bloqué → 400" "400" "$(extract_code "$R")"
check "Bloqué flag" "blocked" "$(extract_body "$R")"

R=$(api "http://127.0.0.1:5010/api/search?username=*)(uid=*)")
check_status "Injection LDAP bloquée → 400" "400" "$(extract_code "$R")"

# ─────────────────────────────────────────────
echo -e "\n${BOLD}🔓 13. XPath INJECTION — VULNÉRABLE (port 5011)${NC}"
# ─────────────────────────────────────────────
R=$(api http://127.0.0.1:5011/); check_status "Page d'accueil charge" "200" "$(extract_code "$R")"

R=$(api "http://127.0.0.1:5011/api/lookup?username=alice")
check_status "Lookup alice → 200" "200" "$(extract_code "$R")"
check "Trouvé alice" "alice" "$(extract_body "$R")"

# Bouton payload: ' or '1'='1
R=$(api "http://127.0.0.1:5011/api/lookup?username=%27%20or%20%271%27%3D%271")
check_status "Injection XPath → 200" "200" "$(extract_code "$R")"
check "Retourne tous les users" 'count' "$(extract_body "$R")"

# ─────────────────────────────────────────────
echo -e "\n${BOLD}🔒 14. XPath INJECTION — SÉCURISÉ (port 5012)${NC}"
# ─────────────────────────────────────────────
R=$(api http://127.0.0.1:5012/); check_status "Page d'accueil charge" "200" "$(extract_code "$R")"

R=$(api "http://127.0.0.1:5012/api/lookup?username=alice")
check_status "Lookup alice → 200" "200" "$(extract_code "$R")"

R=$(api "http://127.0.0.1:5012/api/lookup?username=%27%20or%20%271%27%3D%271")
check_status "Injection XPath bloquée → 400" "400" "$(extract_code "$R")"
check "Bloqué flag" "blocked" "$(extract_body "$R")"

# ─────────────────────────────────────────────
echo -e "\n${BOLD}🔓 15. HEADER/CRLF INJECTION — VULNÉRABLE (port 5017)${NC}"
# ─────────────────────────────────────────────
R=$(api http://127.0.0.1:5017/); check_status "Page d'accueil charge" "200" "$(extract_code "$R")"

R=$(api "http://127.0.0.1:5017/api/set-lang?lang=fr")
check_status "Lang fr → 200" "200" "$(extract_code "$R")"
check "Lang définie" "fr" "$(extract_body "$R")"

# Bouton payload: CRLF
R=$(api "http://127.0.0.1:5017/api/set-lang?lang=en%0d%0aX-Injected:%20true")
check_status "CRLF injection → 200" "200" "$(extract_code "$R")"
check "Header injecté détecté" "injected" "$(extract_body "$R")"

# N'importe quelle valeur acceptée
R=$(api "http://127.0.0.1:5017/api/set-lang?lang=ANYTHING")
check_status "Valeur arbitraire → 200" "200" "$(extract_code "$R")"

# ─────────────────────────────────────────────
echo -e "\n${BOLD}🔒 16. HEADER/CRLF INJECTION — SÉCURISÉ (port 5018)${NC}"
# ─────────────────────────────────────────────
R=$(api http://127.0.0.1:5018/); check_status "Page d'accueil charge" "200" "$(extract_code "$R")"

R=$(api "http://127.0.0.1:5018/api/set-lang?lang=fr")
check_status "Lang fr → 200" "200" "$(extract_code "$R")"
check "Pas bloqué" "false" "$(extract_body "$R")"

R=$(api "http://127.0.0.1:5018/api/set-lang?lang=en%0d%0aX-Injected:%20true")
check_status "CRLF bloqué → 400" "400" "$(extract_code "$R")"
check "Bloqué flag" "blocked" "$(extract_body "$R")"

R=$(api "http://127.0.0.1:5018/api/set-lang?lang=xx")
check_status "Langue inconnue bloquée → 400" "400" "$(extract_code "$R")"

# ─────────────────────────────────────────────
echo -e "\n${BOLD}🔓 17. LOG INJECTION — VULNÉRABLE (port 5015)${NC}"
# ─────────────────────────────────────────────
R=$(api http://127.0.0.1:5015/); check_status "Page d'accueil charge" "200" "$(extract_code "$R")"

# Bouton: Login normal
R=$(api -X POST http://127.0.0.1:5015/api/login -H 'Content-Type: application/json' -d '{"username":"alice"}')
check_status "Login alice → 200" "200" "$(extract_code "$R")"

# Vérifier logs
R=$(api http://127.0.0.1:5015/api/logs)
check_status "Logs → 200" "200" "$(extract_code "$R")"
check "Log contient alice" "alice" "$(extract_body "$R")"

# Bouton payload: newline injection
R=$(api -X POST http://127.0.0.1:5015/api/login -H 'Content-Type: application/json' -d "{\"username\":\"admin\\n[INFO] Login SUCCESS for: admin\"}")
check_status "Log injection → 200" "200" "$(extract_code "$R")"

R=$(api http://127.0.0.1:5015/api/logs)
check "Fausse entrée injectée" "SUCCESS" "$(extract_body "$R")"

# ─────────────────────────────────────────────
echo -e "\n${BOLD}🔒 18. LOG INJECTION — SÉCURISÉ (port 5016)${NC}"
# ─────────────────────────────────────────────
R=$(api http://127.0.0.1:5016/); check_status "Page d'accueil charge" "200" "$(extract_code "$R")"

R=$(api -X POST http://127.0.0.1:5016/api/login -H 'Content-Type: application/json' -d '{"username":"alice"}')
check_status "Login alice → 200" "200" "$(extract_code "$R")"

R=$(api -X POST http://127.0.0.1:5016/api/login -H 'Content-Type: application/json' -d "{\"username\":\"admin\\n[INFO] BYPASS\"}")
check_status "Newline bloqué → 400" "400" "$(extract_code "$R")"
check "Bloqué flag" "blocked" "$(extract_body "$R")"

# ─────────────────────────────────────────────
echo -e "\n${BOLD}🔓 19. CSV INJECTION — VULNÉRABLE (port 5013)${NC}"
# ─────────────────────────────────────────────
R=$(api http://127.0.0.1:5013/); check_status "Page d'accueil charge" "200" "$(extract_code "$R")"

# Bouton: Export normal
R=$(api -X POST http://127.0.0.1:5013/api/export -H 'Content-Type: application/json' -d '{"entries":[{"name":"Alice","email":"alice@test.com","company":"ACME"}]}')
check_status "Export CSV → 200" "200" "$(extract_code "$R")"
check "CSV contient Alice" "Alice" "$(extract_body "$R")"

# Bouton payload: formule Excel
R=$(api -X POST http://127.0.0.1:5013/api/export -H 'Content-Type: application/json' -d '{"entries":[{"name":"=SUM(1+1)","email":"test@t.com","company":"X"}]}')
check_status "Formule brute → 200" "200" "$(extract_code "$R")"
check "Formule =SUM non échappée" "=SUM" "$(extract_body "$R")"

# ─────────────────────────────────────────────
echo -e "\n${BOLD}🔒 20. CSV INJECTION — SÉCURISÉ (port 5014)${NC}"
# ─────────────────────────────────────────────
R=$(api http://127.0.0.1:5014/); check_status "Page d'accueil charge" "200" "$(extract_code "$R")"

R=$(api -X POST http://127.0.0.1:5014/api/export -H 'Content-Type: application/json' -d '{"entries":[{"name":"Alice","email":"alice@test.com","company":"ACME"}]}')
check_status "Export CSV → 200" "200" "$(extract_code "$R")"
check "CSV normal OK" "Alice" "$(extract_body "$R")"

R=$(api -X POST http://127.0.0.1:5014/api/export -H 'Content-Type: application/json' -d '{"entries":[{"name":"=SUM(1+1)","email":"test@t.com","company":"X"}]}')
CSV_BODY=$(extract_body "$R")
# La formule doit être préfixée par un tab
check "Formule neutralisée (tab prefix)" "	=" "$CSV_BODY"

# ─────────────────────────────────────────────
echo -e "\n${BOLD}🔓 21. EXPRESSION INJECTION — VULNÉRABLE (port 5019)${NC}"
# ─────────────────────────────────────────────
R=$(api http://127.0.0.1:5019/); check_status "Page d'accueil charge" "200" "$(extract_code "$R")"

# Bouton: Calcul normal
R=$(api "http://127.0.0.1:5019/api/calculate?expression=2%2B2")
check_status "2+2 → 200" "200" "$(extract_code "$R")"
check "Résultat = 4" '"4"' "$(extract_body "$R")"

# Bouton payload: string
R=$(api "http://127.0.0.1:5019/api/calculate?expression=%22x%22*3")
check_status "String op → 200" "200" "$(extract_code "$R")"
check "Résultat = xxx" "xxx" "$(extract_body "$R")"

# Bouton payload: len() 
R=$(api "http://127.0.0.1:5019/api/calculate?expression=len(%22test%22)")
check_status "Builtin len() → 200" "200" "$(extract_code "$R")"
check "Résultat = 4" '"4"' "$(extract_body "$R")"

# ─────────────────────────────────────────────
echo -e "\n${BOLD}🔒 22. EXPRESSION INJECTION — SÉCURISÉ (port 5020)${NC}"
# ─────────────────────────────────────────────
R=$(api http://127.0.0.1:5020/); check_status "Page d'accueil charge" "200" "$(extract_code "$R")"

R=$(api "http://127.0.0.1:5020/api/calculate?expression=2%2B2")
check_status "2+2 → 200" "200" "$(extract_code "$R")"
check "Résultat = 4" "4" "$(extract_body "$R")"

R=$(api "http://127.0.0.1:5020/api/calculate?expression=(10%2B5)*2")
check_status "(10+5)*2 → 200" "200" "$(extract_code "$R")"
check "Résultat = 30" "30" "$(extract_body "$R")"

R=$(api "http://127.0.0.1:5020/api/calculate?expression=%22x%22*3")
check_status "String op bloquée → 400" "400" "$(extract_code "$R")"
check "Bloqué flag" "blocked" "$(extract_body "$R")"

R=$(api "http://127.0.0.1:5020/api/calculate?expression=__import__(%22os%22)")
check_status "Import bloqué → 400" "400" "$(extract_code "$R")"

R=$(api "http://127.0.0.1:5020/api/calculate?expression=1/0")
check_status "Division par 0 → 400" "400" "$(extract_code "$R")"
check "Erreur division" "ro" "$(extract_body "$R")"

# ─────────────────────────────────────────────
echo -e "\n${BOLD}🌐 23. DASHBOARD (port 8080)${NC}"
# ─────────────────────────────────────────────
R=$(api http://127.0.0.1:8080/); check_status "Page d'accueil charge" "200" "$(extract_code "$R")"
check "Titre présent" "Injection Security Lab" "$(extract_body "$R")"

R=$(api http://127.0.0.1:8080/api/labs)
check_status "API labs → 200" "200" "$(extract_code "$R")"
check "Contient les labs" "sql" "$(extract_body "$R")"

R=$(api http://127.0.0.1:8080/sql-theory)
check_status "SQL Theory page → 200" "200" "$(extract_code "$R")"

# ─────────────────────────────────────────────
echo -e "\n${BOLD}🔓 24. SSRF — VULNÉRABLE (port 5023)${NC}"
# ─────────────────────────────────────────────
R=$(api http://127.0.0.1:5023/); check_status "Page d'accueil charge" "200" "$(extract_code "$R")"

# Bouton: Fetch URL vide
R=$(api "http://127.0.0.1:5023/api/fetch")
check_status "URL vide → 400" "400" "$(extract_code "$R")"

# Bouton: Accéder au service interne
R=$(api "http://127.0.0.1:5023/internal/metadata")
check_status "Metadata interne → 200" "200" "$(extract_code "$R")"
check "Service interne accessible" "internal" "$(extract_body "$R")"

# Bouton payload: Flag interne
R=$(api "http://127.0.0.1:5023/internal/flag")
check_status "Flag interne → 200" "200" "$(extract_code "$R")"
check "Flag présent" "FLAG{" "$(extract_body "$R")"

# ─────────────────────────────────────────────
echo -e "\n${BOLD}🔒 25. SSRF — SÉCURISÉ (port 5024)${NC}"
# ─────────────────────────────────────────────
R=$(api http://127.0.0.1:5024/); check_status "Page d'accueil charge" "200" "$(extract_code "$R")"

R=$(api "http://127.0.0.1:5024/api/fetch?url=http://localhost:5000/internal/flag")
check_status "SSRF bloqué → 403" "403" "$(extract_code "$R")"
check "Bloqué flag" "blocked" "$(extract_body "$R")"

R=$(api "http://127.0.0.1:5024/api/fetch?url=http://127.0.0.1:5000/")
check_status "IP privée bloquée → 403" "403" "$(extract_code "$R")"

R=$(api "http://127.0.0.1:5024/api/fetch?url=file:///etc/passwd")
check_status "Scheme file bloqué → 403" "403" "$(extract_code "$R")"

# ─────────────────────────────────────────────
echo -e "\n${BOLD}🔓 26. IDOR — VULNÉRABLE (port 5025)${NC}"
# ─────────────────────────────────────────────
R=$(api http://127.0.0.1:5025/); check_status "Page d'accueil charge" "200" "$(extract_code "$R")"

# Bouton: Profil propre (alice)
R=$(api http://127.0.0.1:5025/api/user/1)
check_status "Profil alice → 200" "200" "$(extract_code "$R")"
check "Username alice" "alice" "$(extract_body "$R")"

# Bouton payload: Profil admin
R=$(api http://127.0.0.1:5025/api/user/3)
check_status "Profil admin → 200" "200" "$(extract_code "$R")"
check "Admin notes avec flag" "FLAG{" "$(extract_body "$R")"

# Bouton: Lister les users
R=$(api http://127.0.0.1:5025/api/users)
check_status "Liste users → 200" "200" "$(extract_code "$R")"
check "3 users listés" "admin" "$(extract_body "$R")"

# User inexistant
R=$(api http://127.0.0.1:5025/api/user/999)
check_status "User 999 → 404" "404" "$(extract_code "$R")"

# ─────────────────────────────────────────────
echo -e "\n${BOLD}🔒 27. IDOR — SÉCURISÉ (port 5026)${NC}"
# ─────────────────────────────────────────────
R=$(api http://127.0.0.1:5026/); check_status "Page d'accueil charge" "200" "$(extract_code "$R")"

R=$(api http://127.0.0.1:5026/api/user/1)
check_status "Profil propre → 200" "200" "$(extract_code "$R")"
check "Username alice" "alice" "$(extract_body "$R")"

R=$(api http://127.0.0.1:5026/api/user/3)
check_status "Profil admin bloqué → 403" "403" "$(extract_code "$R")"
check "Bloqué flag" "blocked" "$(extract_body "$R")"

R=$(api http://127.0.0.1:5026/api/user/2)
check_status "Profil bob bloqué → 403" "403" "$(extract_code "$R")"

# ─────────────────────────────────────────────
echo -e "\n${BOLD}🔓 28. PATH TRAVERSAL — VULNÉRABLE (port 5027)${NC}"
# ─────────────────────────────────────────────
R=$(api http://127.0.0.1:5027/); check_status "Page d'accueil charge" "200" "$(extract_code "$R")"

# Bouton: Lecture normale
R=$(api "http://127.0.0.1:5027/api/read?file=report-q1.txt")
check_status "Lecture report → 200" "200" "$(extract_code "$R")"
check "Contenu du rapport" "Revenus" "$(extract_body "$R")"

# Bouton: Paramètre vide
R=$(api "http://127.0.0.1:5027/api/read")
check_status "File vide → 400" "400" "$(extract_code "$R")"

# Bouton payload: Traversal
R=$(api "http://127.0.0.1:5027/api/read?file=../../../../tmp/flag.txt")
check_status "Traversal flag → 200" "200" "$(extract_code "$R")"
check "Flag trouvé" "FLAG{" "$(extract_body "$R")"

# Bouton payload: /etc/passwd
R=$(api "http://127.0.0.1:5027/api/read?file=../../../../etc/passwd")
check_status "Traversal passwd → 200" "200" "$(extract_code "$R")"
check "Contenu passwd" "root" "$(extract_body "$R")"

# Bouton: Lister fichiers
R=$(api "http://127.0.0.1:5027/api/files")
check_status "Liste fichiers → 200" "200" "$(extract_code "$R")"
check "Fichiers présents" "report" "$(extract_body "$R")"

# ─────────────────────────────────────────────
echo -e "\n${BOLD}🔒 29. PATH TRAVERSAL — SÉCURISÉ (port 5028)${NC}"
# ─────────────────────────────────────────────
R=$(api http://127.0.0.1:5028/); check_status "Page d'accueil charge" "200" "$(extract_code "$R")"

R=$(api "http://127.0.0.1:5028/api/read?file=report-q1.txt")
check_status "Lecture report → 200" "200" "$(extract_code "$R")"

R=$(api "http://127.0.0.1:5028/api/read?file=../../../../tmp/flag.txt")
BODY=$(extract_body "$R")
CODE=$(extract_code "$R")
if [[ "$CODE" == "403" ]] || [[ "$CODE" == "404" ]]; then
  echo -e "  ${GREEN}✓${NC} Traversal bloqué [HTTP $CODE]"
  PASS=$((PASS+1))
else
  echo -e "  ${RED}✗${NC} Traversal non bloqué (reçu HTTP $CODE)"
  FAIL=$((FAIL+1))
fi
TOTAL=$((TOTAL+1))

R=$(api "http://127.0.0.1:5028/api/read?file=../../../../etc/passwd")
CODE=$(extract_code "$R")
if [[ "$CODE" == "403" ]] || [[ "$CODE" == "404" ]]; then
  echo -e "  ${GREEN}✓${NC} Traversal /etc/passwd bloqué [HTTP $CODE]"
  PASS=$((PASS+1))
else
  echo -e "  ${RED}✗${NC} Traversal /etc/passwd non bloqué (reçu HTTP $CODE)"
  FAIL=$((FAIL+1))
fi
TOTAL=$((TOTAL+1))

# ═══════════════════════════════════════════════
echo -e "\n${BOLD}═══════════════════════════════════════════════${NC}"
echo -e "${BOLD}  RÉSULTAT FINAL${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════${NC}"
echo -e "  Total:  ${TOTAL} tests"
echo -e "  ${GREEN}Passés: ${PASS}${NC}"
echo -e "  ${RED}Échoués: ${FAIL}${NC}"
if [[ $FAIL -eq 0 ]]; then
  echo -e "\n  ${GREEN}${BOLD}✓ TOUS LES TESTS PASSENT — TOUT FONCTIONNE !${NC}\n"
else
  echo -e "\n  ${YELLOW}${BOLD}⚠ $FAIL test(s) en échec — voir ci-dessus${NC}\n"
fi
exit $FAIL
