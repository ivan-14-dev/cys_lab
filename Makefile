.PHONY: build up down restart test logs clean \
        lab-xss lab-command lab-ssti lab-nosql lab-ldap lab-xpath \
        lab-csv lab-log lab-header lab-expression help

COMPOSE = docker compose
ENV_FILE = .env

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build all lab containers
	@echo "==> Building all lab containers..."
	$(COMPOSE) --env-file $(ENV_FILE) build

up: ## Start the full lab
	@echo "==> Starting Injection Security Lab..."
	$(COMPOSE) --env-file $(ENV_FILE) up -d
	@echo ""
	@echo "  Dashboard:          http://localhost:8080"
	@echo "  XSS Vulnerable:     http://localhost:5001"
	@echo "  XSS Secure:         http://localhost:5002"
	@echo "  Command Vuln:       http://localhost:5003"
	@echo "  Command Secure:     http://localhost:5004"
	@echo "  SSTI Vulnerable:    http://localhost:5005"
	@echo "  SSTI Secure:        http://localhost:5006"
	@echo "  NoSQL Vulnerable:   http://localhost:5007"
	@echo "  NoSQL Secure:       http://localhost:5008"
	@echo "  LDAP Vulnerable:    http://localhost:5009"
	@echo "  LDAP Secure:        http://localhost:5010"
	@echo "  XPath Vulnerable:   http://localhost:5011"
	@echo "  XPath Secure:       http://localhost:5012"
	@echo "  CSV Vulnerable:     http://localhost:5013"
	@echo "  CSV Secure:         http://localhost:5014"
	@echo "  Log Vulnerable:     http://localhost:5015"
	@echo "  Log Secure:         http://localhost:5016"
	@echo "  Header Vulnerable:  http://localhost:5017"
	@echo "  Header Secure:      http://localhost:5018"
	@echo "  Expr Vulnerable:    http://localhost:5019"
	@echo "  Expr Secure:        http://localhost:5020"

down: ## Stop the lab
	@echo "==> Stopping Injection Security Lab..."
	$(COMPOSE) --env-file $(ENV_FILE) down

restart: down up ## Restart the lab

test: ## Run all automated tests
	@echo "==> Running all lab tests..."
	@for lab in xss command-injection ssti nosql-injection ldap-injection \
	             xpath-injection csv-injection log-injection \
	             header-injection expression-injection; do \
		echo ""; \
		echo "--- Testing: $$lab ---"; \
		cd labs/$$lab && python -m pytest tests/ -v --tb=short 2>&1 || true; \
		cd ../..; \
	done

logs: ## View all container logs
	$(COMPOSE) --env-file $(ENV_FILE) logs -f

clean: ## Remove containers, volumes, and built images
	@echo "==> Cleaning up..."
	$(COMPOSE) --env-file $(ENV_FILE) down -v --rmi local
	@echo "Done."

# --- Individual lab targets ---

lab-xss: ## Start only the XSS lab
	$(COMPOSE) --env-file $(ENV_FILE) up -d xss-vulnerable xss-secure
	@echo "XSS Vulnerable: http://localhost:5001"
	@echo "XSS Secure:     http://localhost:5002"

lab-command: ## Start only the Command Injection lab
	$(COMPOSE) --env-file $(ENV_FILE) up -d cmd-vulnerable cmd-secure
	@echo "Command Vuln:   http://localhost:5003"
	@echo "Command Secure: http://localhost:5004"

lab-ssti: ## Start only the SSTI lab
	$(COMPOSE) --env-file $(ENV_FILE) up -d ssti-vulnerable ssti-secure
	@echo "SSTI Vulnerable: http://localhost:5005"
	@echo "SSTI Secure:     http://localhost:5006"

lab-nosql: ## Start only the NoSQL Injection lab
	$(COMPOSE) --env-file $(ENV_FILE) up -d mongodb nosql-vulnerable nosql-secure
	@echo "NoSQL Vulnerable: http://localhost:5007"
	@echo "NoSQL Secure:     http://localhost:5008"

lab-ldap: ## Start only the LDAP Injection lab
	$(COMPOSE) --env-file $(ENV_FILE) up -d openldap ldap-vulnerable ldap-secure
	@echo "LDAP Vulnerable: http://localhost:5009"
	@echo "LDAP Secure:     http://localhost:5010"

lab-xpath: ## Start only the XPath Injection lab
	$(COMPOSE) --env-file $(ENV_FILE) up -d xpath-vulnerable xpath-secure
	@echo "XPath Vulnerable: http://localhost:5011"
	@echo "XPath Secure:     http://localhost:5012"

lab-csv: ## Start only the CSV Injection lab
	$(COMPOSE) --env-file $(ENV_FILE) up -d csv-vulnerable csv-secure
	@echo "CSV Vulnerable: http://localhost:5013"
	@echo "CSV Secure:     http://localhost:5014"

lab-log: ## Start only the Log Injection lab
	$(COMPOSE) --env-file $(ENV_FILE) up -d log-vulnerable log-secure
	@echo "Log Vulnerable: http://localhost:5015"
	@echo "Log Secure:     http://localhost:5016"

lab-header: ## Start only the Header Injection lab
	$(COMPOSE) --env-file $(ENV_FILE) up -d header-vulnerable header-secure
	@echo "Header Vulnerable: http://localhost:5017"
	@echo "Header Secure:     http://localhost:5018"

lab-expression: ## Start only the Expression Injection lab
	$(COMPOSE) --env-file $(ENV_FILE) up -d expr-vulnerable expr-secure
	@echo "Expr Vulnerable: http://localhost:5019"
	@echo "Expr Secure:     http://localhost:5020"
