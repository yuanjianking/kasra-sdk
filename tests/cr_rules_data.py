# Auto-generated from DB (83 rules)
CR_RULES = [
  {
    "id": "SEC-01",
    "name": "Hardcoded Cloud Credentials",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "AKIA[0-9A-Z]{16}\\b",
          "confidence": 0.95
        },
        {
          "type": "regex",
          "value": "ghp_[0-9A-Za-z]{36,40}\\b",
          "confidence": 0.95
        },
        {
          "type": "regex",
          "value": "gh[oausr]_[0-9A-Za-z]{36}\\b",
          "confidence": 0.9
        },
        {
          "type": "regex",
          "value": "glpat-[0-9A-Za-z\\-_]{20,40}\\b",
          "confidence": 0.9
        },
        {
          "type": "regex",
          "value": "sk-[a-zA-Z0-9]{20,50}\\b",
          "confidence": 0.9
        },
        {
          "type": "regex",
          "value": "sk-ant-[a-zA-Z0-9]{40,60}\\b",
          "confidence": 0.9
        },
        {
          "type": "regex",
          "value": "(?i)-----BEGIN\\s+(?:RSA\\s+)?PRIVATE\\s+KEY-----",
          "confidence": 0.95
        },
        {
          "type": "regex",
          "value": "(?i)-----BEGIN\\s+(?:OPEN)?SSH\\s+PRIVATE\\s+KEY-----",
          "confidence": 0.95
        },
        {
          "type": "regex",
          "value": "(?i)-----BEGIN\\s+PGP\\s+(?:PRIVATE\\s+)?KEY\\s+BLOCK-----",
          "confidence": 0.9
        },
        {
          "type": "regex",
          "value": "\\beyJ[A-Za-z0-9\\-_]+\\.[A-Za-z0-9\\-_]+\\.[A-Za-z0-9\\-_]+\\b",
          "confidence": 0.7
        },
        {
          "type": "regex",
          "value": "sk_live_[a-zA-Z0-9]{24,}\\b",
          "confidence": 0.95
        },
        {
          "type": "regex",
          "value": "pk_live_[a-zA-Z0-9]{24,}\\b",
          "confidence": 0.9
        },
        {
          "type": "regex",
          "value": "\\bAIza[0-9A-Za-z\\-_]{35}\\b",
          "confidence": 0.9
        }
      ]
    }
  },
  {
    "id": "SEC-02",
    "name": "Hardcoded Passwords / Connection Strings",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "[a-zA-Z]+://[^:]+:[^@]+@[^/\\s]+",
          "confidence": 0.85
        },
        {
          "type": "regex",
          "value": "(?i)(?:jdbc|mysql|postgres|mongodb|redis|rediss|rabbitmq|amqp|kafka|sqs|memcache|hbase|cassandra)://[^\\s'\"]+",
          "confidence": 0.8
        },
        {
          "type": "regex",
          "value": "(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+",
          "confidence": 0.9
        },
        {
          "type": "regex",
          "value": "ssh://[^:]+:[^@]+@",
          "confidence": 0.85
        },
        {
          "type": "regex",
          "value": "(?i)(?:password|passwd|pwd)\\s*[:=]\\s*['\"][^'\"]{3,}['\"]",
          "confidence": 0.6
        }
      ]
    }
  },
  {
    "id": "SEC-03",
    "name": "Hardcoded Cryptographic Keys",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "(?i)(?:aes|secret|hmac|jwt_?secret|signing_?key|token_?secret)\\s*[:=]\\s*['\"][A-Za-z0-9\\+\\/=]{16,}['\"]",
          "confidence": 0.7
        },
        {
          "type": "regex",
          "value": "(?i)(?:salt|pepper)\\s*[:=]\\s*['\"][A-Za-z0-9\\+\\/=]{8,}['\"]",
          "confidence": 0.6
        },
        {
          "type": "regex",
          "value": "(?i)jwt\\.(?:sign|encode)\\([^)]*['\"]secret['\"]",
          "confidence": 0.8
        },
        {
          "type": "regex",
          "value": "(?i)(?:jwt[_-]?secret|signing[_-]?key|secret[_-]?key)\\s*[:=]\\s*[\\\"'].{8,}[\\\"']",
          "confidence": 0.65
        }
      ]
    }
  },
  {
    "id": "SEC-04",
    "name": "Test Credentials Leftover",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "(?i)(?:password|passwd|pwd)\\s*[:=]\\s*['\"](?:password123|admin123|test123|P@ssw0rd|letmein|welcome|changeme|passw0rd)['\"]",
          "confidence": 0.85
        },
        {
          "type": "regex",
          "value": "(?i)(?:username|user|login)\\s*[:=]\\s*['\"](?:admin|root|test|guest|sa)['\"]\\s*[,;]\\s*(?:\\n|\\s)*(?:password|passwd|pwd)\\s*[:=]\\s*['\"](?:admin|root|test|guest|sa|password)['\"]",
          "confidence": 0.8
        },
        {
          "type": "regex",
          "value": "[\"\\'](?:password|passwd|pwd)[\"\\']?\\s*:\\s*[\"\\'](?:password123|admin|test|123456)",
          "confidence": 0.6
        }
      ]
    }
  },
  {
    "id": "SEC-05",
    "name": "SQL Injection",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": []
    }
  },
  {
    "id": "SEC-07",
    "name": "OS Command Injection",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": []
    }
  },
  {
    "id": "SEC-08",
    "name": "Unsafe Deserialization",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": []
    }
  },
  {
    "id": "SEC-09",
    "name": "XXE (XML External Entity Injection)",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "etree\\.(?:fromstring|parse|XML)\\s*\\(",
          "confidence": 0.65
        }
      ]
    }
  },
  {
    "id": "SEC-14",
    "name": "Code Injection (eval/exec)",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "\\beval\\s*\\(",
          "confidence": 0.7
        }
      ]
    }
  },
  {
    "id": "SEC-15",
    "name": "Cross-Site Scripting (XSS)",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": []
    }
  },
  {
    "id": "SEC-19",
    "name": "Server-Side Request Forgery (SSRF)",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": []
    }
  },
  {
    "id": "SEC-21",
    "name": "Unrestricted File Upload",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": []
    }
  },
  {
    "id": "SEC-23",
    "name": "Local/Remote File Inclusion (LFI/RFI)",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": []
    }
  },
  {
    "id": "SEC-37",
    "name": "Debug Mode / Information Leak",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "config_keyvalue",
          "value": "DEBUG:^(?:True|true|1)$",
          "confidence": 0.9
        },
        {
          "type": "config_keyvalue",
          "value": "FLASK_DEBUG:^(?:True|true|1)$",
          "confidence": 0.9
        },
        {
          "type": "config_keyvalue",
          "value": "NODE_ENV:^development$",
          "confidence": 0.9
        },
        {
          "type": "regex",
          "value": "(?i)\\\\bapp\\\\.run\\\\([^)]*debug\\\\s*=\\\\s*True",
          "confidence": 0.85
        },
        {
          "type": "regex",
          "value": "(?i)\\\\bapp\\\\.run\\\\([^)]*debug\\\\s*=\\s*True",
          "confidence": 0.85
        },
        {
          "type": "regex",
          "value": "(?i)app\\.run\\([^)]*debug\\s*=\\s*True",
          "confidence": 0.85
        }
      ]
    }
  },
  {
    "id": "SEC-40",
    "name": "Known CVE Dependencies",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "flask==0\\.12\\.|flask==0\\.11\\.|flask==0\\.10\\.",
          "confidence": 0.65
        },
        {
          "type": "regex",
          "value": "flask==0\\.12",
          "confidence": 0.65
        }
      ]
    }
  },
  {
    "id": "SEC-45",
    "name": "Path Traversal",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "os\\.path\\.join\\s*\\([^)]*\\w+(?:input|user|file|name|path|filename|fn)\\s*,",
          "confidence": 0.55
        },
        {
          "type": "regex",
          "value": "os\\.path\\.join\\s*\\(",
          "confidence": 0.45
        }
      ]
    }
  },
  {
    "id": "SEC-51",
    "name": "Unsafe Direct Command Execution",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": []
    }
  },
  {
    "id": "SEC-06",
    "name": "NoSQL Injection",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "\\$where\\s*'?\\s*:",
          "confidence": 0.7
        },
        {
          "type": "regex",
          "value": "findByIdAnd(?:Update|Delete)\\s*\\(\\s*\\w+\\s*,",
          "confidence": 0.65
        }
      ]
    }
  },
  {
    "id": "SEC-10",
    "name": "LDAP Injection",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "['\\\"][^'\\\"]*\\b(?:uid|cn|sn|mail)\\s*=\\s*['\\\"]\\s*\\+\\s*\\w+",
          "confidence": 0.7
        },
        {
          "type": "regex",
          "value": "\\b(?:uid|cn|sn|mail)\\s*=\\s*['\\\"].*\\+\\s*\\w+",
          "confidence": 0.65
        },
        {
          "type": "regex",
          "value": "['\\\"][^'\\\"]*\\b(?:uid|cn|sn|mail)\\s*=\\s*['\\\"]\\s*\\+\\s*\\w+",
          "confidence": 0.65
        }
      ]
    }
  },
  {
    "id": "SEC-11",
    "name": "SSTI (Server-Side Template Injection)",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "render_template_string\\s*\\(\\s*(?:f['\\\"]|['\\\"][^'\\\"]*\\+)",
          "confidence": 0.75
        },
        {
          "type": "regex",
          "value": "Handlebars\\.compile\\s*\\(\\s*\\w+\\s*\\+",
          "confidence": 0.65
        }
      ]
    }
  },
  {
    "id": "SEC-13",
    "name": "Prototype Pollution",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "_\\.(?:merge|defaults|assign)\\s*\\([^)]*\\b(?:body|input|query|param|user)",
          "confidence": 0.65
        },
        {
          "type": "regex",
          "value": "\\[\\s*['\\\"]__proto__['\\\"]\\s*\\]",
          "confidence": 0.75
        },
        {
          "type": "regex",
          "value": "_\\.(?:merge|defaults|assign)\\s*\\(",
          "confidence": 0.6
        }
      ]
    }
  },
  {
    "id": "SEC-16",
    "name": "CORS Misconfiguration",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "config_keyvalue",
          "value": "CORS_ALLOW_ALL_ORIGINS:^(?:True|true)$",
          "confidence": 0.85
        },
        {
          "type": "regex",
          "value": "(?i)cors\\(\\{.*origin\\s*:\\s*true.*credentials\\s*:\\s*true",
          "confidence": 0.8
        },
        {
          "type": "regex",
          "value": "(?i)AllowAnyOrigin.*SupportsCredentials",
          "confidence": 0.8
        },
        {
          "type": "regex",
          "value": "(?i)cors\\(.*origins?\\s*=\\s*[\"\\'].*\\*",
          "confidence": 0.65
        }
      ]
    }
  },
  {
    "id": "SEC-17",
    "name": "CSRF Protection Missing",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": []
    }
  },
  {
    "id": "SEC-20",
    "name": "Open Redirect",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "redirect\\s*\\(\\s*(?:request|req)\\.",
          "confidence": 0.55
        },
        {
          "type": "regex",
          "value": "redirect\\s*\\(",
          "confidence": 0.35
        }
      ]
    }
  },
  {
    "id": "SEC-24",
    "name": "Mass Assignment",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "\\.(?:create|update|save|findByIdAndUpdate)\\s*\\(\\s*(?:req|request)\\.",
          "confidence": 0.6
        }
      ]
    }
  },
  {
    "id": "SEC-25",
    "name": "JWT Security Defects",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "jwt\\.decode\\s*\\(\\s*\\w+\\s*,\\s*\\{",
          "confidence": 0.7
        },
        {
          "type": "regex",
          "value": "jwt\\.decode\\s*\\(",
          "confidence": 0.65
        }
      ]
    }
  },
  {
    "id": "SEC-32",
    "name": "Weak Cryptographic Algorithms",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": []
    }
  },
  {
    "id": "SEC-33",
    "name": "Insecure Randomness",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": []
    }
  },
  {
    "id": "SEC-34",
    "name": "TLS/SSL Certificate Validation Disabled",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "ssl\\._create_default_https_context\\s*=\\s*ssl\\._create_unverified_context",
          "confidence": 0.85
        }
      ]
    }
  },
  {
    "id": "SEC-36",
    "name": "CI Script Risks",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "curl\\s+.*\\|\\s*bash\\b",
          "confidence": 0.85
        },
        {
          "type": "regex",
          "value": "setenforce\\s+0|ufw\\s+disable|iptables\\s+-F",
          "confidence": 0.85
        },
        {
          "type": "regex",
          "value": "(?i)--no-verify\\b|--no-audit\\b",
          "confidence": 0.7
        }
      ]
    }
  },
  {
    "id": "SEC-38",
    "name": "Insecure Configuration Defaults",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "config_keyvalue",
          "value": "SECRET_KEY:changeme|secret|password|default|development",
          "confidence": 0.75
        },
        {
          "type": "regex",
          "value": "ALLOWED_HOSTS\\s*=\\s*\\[\\s*['\\\"]\\*['\\\"]\\s*\\]",
          "confidence": 0.85
        },
        {
          "type": "config_keyvalue",
          "value": "SESSION_COOKIE_SECURE:^false$",
          "confidence": 0.7
        }
      ]
    }
  },
  {
    "id": "SEC-42",
    "name": "Plaintext Communication",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "http://\\w+\\.(?:com|org|net|io|app|dev)",
          "confidence": 0.55
        },
        {
          "type": "regex",
          "value": "ws://\\w+",
          "confidence": 0.7
        },
        {
          "type": "regex",
          "value": "ftp://[^@]+:[^@]+@",
          "confidence": 0.75
        },
        {
          "type": "regex",
          "value": "(?i)endpoint_url\\s*[:=]\\s*['\\\"]http://",
          "confidence": 0.65
        },
        {
          "type": "regex",
          "value": "https?://[a-zA-Z0-9.-]+/[a-zA-Z0-9]",
          "confidence": 0.55
        }
      ]
    }
  },
  {
    "id": "SEC-44",
    "name": "CI/CD Attack Surface",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "(?i)self-hosted|self.hosted",
          "confidence": 0.5
        },
        {
          "type": "regex",
          "value": "(?i)permissions:\\s*write-all",
          "confidence": 0.75
        },
        {
          "type": "regex",
          "value": "(?i)contents:\\s*write",
          "confidence": 0.5
        },
        {
          "type": "regex",
          "value": "(?i)permissions:\\s*write-all",
          "confidence": 0.55
        }
      ]
    }
  },
  {
    "id": "IAC-01",
    "name": "Dockerfile Security",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "config_dockerfile",
          "value": "FROM:\\s*:\\s*latest\\b",
          "confidence": 0.7
        },
        {
          "type": "config_dockerfile",
          "value": "USER:^root$",
          "confidence": 0.6
        },
        {
          "type": "config_dockerfile",
          "value": "ADD:^https?://",
          "confidence": 0.6
        }
      ]
    }
  },
  {
    "id": "IAC-04",
    "name": "K8s Workload Security",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "config_yaml",
          "value": "spec.containers.securityContext.privileged:true",
          "confidence": 0.85
        },
        {
          "type": "config_yaml",
          "value": "spec.containers.securityContext.allowPrivilegeEscalation:true",
          "confidence": 0.8
        },
        {
          "type": "config_yaml",
          "value": "spec.hostNetwork:true",
          "confidence": 0.7
        },
        {
          "type": "config_yaml",
          "value": "spec.containers.securityContext.runAsNonRoot:false",
          "confidence": 0.75
        },
        {
          "type": "regex",
          "value": "privileged:\\s*true",
          "confidence": 0.85
        },
        {
          "type": "regex",
          "value": "hostNetwork:\\s*true",
          "confidence": 0.7
        },
        {
          "type": "regex",
          "value": "allowPrivilegeEscalation:\\s*true",
          "confidence": 0.65
        }
      ]
    }
  },
  {
    "id": "IAC-08",
    "name": "Terraform Storage Security",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "acl\\s*=\\s*['\\\"](?:public-read|public-read-write)['\\\"]",
          "confidence": 0.85
        }
      ]
    }
  },
  {
    "id": "SEC-12",
    "name": "Header Injection / CRLF",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "setHeader\\s*\\(\\s*['\\\"][^'\\\"]*['\\\"]\\s*,\\s*\\w+",
          "confidence": 0.55
        }
      ]
    }
  },
  {
    "id": "SEC-26",
    "name": "Security Response Headers Missing",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "(?i)Content-Security-Policy",
          "confidence": 0.5
        },
        {
          "type": "regex",
          "value": "(?i)Strict-Transport-Security",
          "confidence": 0.5
        },
        {
          "type": "regex",
          "value": "(?i)X-Frame-Options",
          "confidence": 0.5
        },
        {
          "type": "regex",
          "value": "(?i)Missing (?:CSP|CORS|security|XSS|X-?Frame)",
          "confidence": 0.5
        },
        {
          "type": "regex",
          "value": "Missing\\s+\\w+\\s+header",
          "confidence": 0.45
        }
      ]
    }
  },
  {
    "id": "SEC-27",
    "name": "Session Management Defects",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "session\\.(?:id|token)\\s*[:=]",
          "confidence": 0.5
        },
        {
          "type": "regex",
          "value": "hashlib\\.md5.*session|session.*hashlib\\.md5|haslib\\.sha1.*session",
          "confidence": 0.55
        },
        {
          "type": "regex",
          "value": "hashlib\\.(?:md5|sha1)\\s*\\(",
          "confidence": 0.5
        }
      ]
    }
  },
  {
    "id": "SEC-28",
    "name": "OAuth / OIDC Security Defects",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "(?i)response_type\\s*['\\\"]token['\\\"]",
          "confidence": 0.7
        },
        {
          "type": "regex",
          "value": "(?i)response_type['\\\"]?\\s*[:=]\\s*['\\\"]token['\\\"]",
          "confidence": 0.6
        }
      ]
    }
  },
  {
    "id": "SEC-29",
    "name": "WebSocket / SSE Security",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "new\\s+WebSocket\\s*\\(\\s*['\\\"]ws://",
          "confidence": 0.75
        }
      ]
    }
  },
  {
    "id": "SEC-30",
    "name": "gRPC Security",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "(?i)insecure\\.NewCredentials\\(\\)",
          "confidence": 0.85
        },
        {
          "type": "regex",
          "value": "(?i)WithInsecure\\s*\\(",
          "confidence": 0.8
        },
        {
          "type": "regex",
          "value": "(?i)insecure_channel|Insecure\\b",
          "confidence": 0.75
        }
      ]
    }
  },
  {
    "id": "SEC-31",
    "name": "GraphQL Security",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "(?i)(?:introspection)\\s*[:=]\\s*true",
          "confidence": 0.7
        },
        {
          "type": "regex",
          "value": "introspection",
          "confidence": 0.55
        }
      ]
    }
  },
  {
    "id": "SEC-35",
    "name": "Insecure Certificate Storage",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "(?i)ALLOW_ALL_HOSTNAME_VERIFIER",
          "confidence": 0.85
        }
      ]
    }
  },
  {
    "id": "SEC-41",
    "name": "Subresource Integrity (SRI) Missing",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "<script\\s+[^>]*src=.*(?:cdn|cloudfront|unpkg|jsdelivr|cdnjs)",
          "confidence": 0.5
        }
      ]
    }
  },
  {
    "id": "SEC-43",
    "name": "Observability Data Leak",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "(?i)/actuator",
          "confidence": 0.5
        },
        {
          "type": "regex",
          "value": "/actuator",
          "confidence": 0.55
        },
        {
          "type": "regex",
          "value": "include:\\s+\"\\*\"",
          "confidence": 0.55
        }
      ]
    }
  },
  {
    "id": "SEC-46",
    "name": "Race Condition / TOCTOU",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "os\\.path\\.(?:exists|isfile|isdir)\\s*\\([^)]*\\).*os\\.(?:remove|unlink|rename)\\s*\\(",
          "confidence": 0.5
        },
        {
          "type": "regex",
          "value": "os\\.path\\.exists\\s*\\(",
          "confidence": 0.4
        }
      ]
    }
  },
  {
    "id": "SEC-47",
    "name": "Resource Exhaustion / DoS",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": []
    }
  },
  {
    "id": "SEC-48",
    "name": "Zip Slip / Archive Extraction",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "\\b(?:extractall|extract)\\s*\\(",
          "confidence": 0.6
        }
      ]
    }
  },
  {
    "id": "SEC-49",
    "name": "Memory Safety",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": []
    }
  },
  {
    "id": "SEC-50",
    "name": "Error Handling Information Leak",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": []
    }
  },
  {
    "id": "SEC-60",
    "name": "WebView Insecure Configuration",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "(?i)setJavaScriptEnabled\\s*\\(\\s*true\\s*\\)",
          "confidence": 0.75
        }
      ]
    }
  },
  {
    "id": "SEC-61",
    "name": "Insecure Local Storage",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "(?i)SharedPreferences\\.(?:putString|getString)\\s*\\(\\s*['\\\"](?:token|password|secret|api_key)",
          "confidence": 0.7
        },
        {
          "type": "regex",
          "value": "SharedPreferences\\.(?:putString|getString)",
          "confidence": 0.55
        },
        {
          "type": "regex",
          "value": "SharedPreferences",
          "confidence": 0.5
        }
      ]
    }
  },
  {
    "id": "SEC-62",
    "name": "Deep Link Hijack",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "android:exported\\s*=\\s*\\\"true\\\"",
          "confidence": 0.5
        },
        {
          "type": "regex",
          "value": "android:exported=\"true\"",
          "confidence": 0.55
        }
      ]
    }
  },
  {
    "id": "SEC-63",
    "name": "Backup Leak",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "android:allowBackup\\s*=\\s*\\\"true\\\"",
          "confidence": 0.7
        },
        {
          "type": "regex",
          "value": "android:allowBackup=\"true\"",
          "confidence": 0.55
        }
      ]
    }
  },
  {
    "id": "SEC-64",
    "name": "Certificate Pinning Missing",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "(?i)CertificatePinner|ServerTrustManager|ssl.?pinning",
          "confidence": 0.5
        },
        {
          "type": "regex",
          "value": "new\\s+OkHttpClient\\s*\\.Builder\\s*\\(\\s*\\)\\s*\\.build\\s*\\(",
          "confidence": 0.4
        }
      ]
    }
  },
  {
    "id": "SEC-65",
    "name": "Screenshot Leak",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "(?i)FLAG_SECURE",
          "confidence": 0.5
        },
        {
          "type": "regex",
          "value": "(?i)FLAG_SECURE",
          "confidence": 0.5
        },
        {
          "type": "regex",
          "value": "FLAG_SECURE",
          "confidence": 0.5
        }
      ]
    }
  },
  {
    "id": "SEC-66",
    "name": "Clipboard Leak",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "(?i)ClipboardManager|UIPasteboard|Clipboard\\.setData",
          "confidence": 0.55
        }
      ]
    }
  },
  {
    "id": "IAC-02",
    "name": "Docker Compose Security",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "ports:\\s*\\n\\s*-\\s*\"0\\.0\\.0\\.0",
          "confidence": 0.7
        },
        {
          "type": "regex",
          "value": "network_mode:\\s*host",
          "confidence": 0.7
        },
        {
          "type": "config_yaml",
          "value": "services.ports:0\\.0\\.0\\.0",
          "confidence": 0.7
        },
        {
          "type": "config_yaml",
          "value": "services.network_mode:host",
          "confidence": 0.7
        },
        {
          "type": "config_yaml",
          "value": "services.environment:.*=.*:",
          "confidence": 0.3
        }
      ]
    }
  },
  {
    "id": "IAC-03",
    "name": "Container Runtime Security",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "config_yaml",
          "value": "spec.containers.securityContext.privileged:true",
          "confidence": 0.85
        },
        {
          "type": "regex",
          "value": "cap_add:\\s*\\n\\s*- SYS_ADMIN",
          "confidence": 0.75
        }
      ]
    }
  },
  {
    "id": "IAC-05",
    "name": "K8s Network & Storage Security",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "config_yaml",
          "value": "spec.containers.volumeMounts.hostPath:.*",
          "confidence": 0.5
        },
        {
          "type": "regex",
          "value": "type:\\s*NodePort",
          "confidence": 0.5
        }
      ]
    }
  },
  {
    "id": "IAC-06",
    "name": "K8s RBAC / Credentials",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "apiGroups[\\s\\S]*?\\*[\\s\\S]*?resources[\\s\\S]*?\\*[\\s\\S]*?verbs[\\s\\S]*?\\*",
          "confidence": 0.85
        },
        {
          "type": "regex",
          "value": "subjects:.*system:authenticated",
          "confidence": 0.7
        }
      ]
    }
  },
  {
    "id": "IAC-07",
    "name": "K8s Config & Secret Security",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "kind:\\s*Secret\\n(?!.*type:\\s*kubernetes.io)",
          "confidence": 0.5
        },
        {
          "type": "regex",
          "value": "kind:\\s*ConfigMap\\b",
          "confidence": 0.3
        }
      ]
    }
  },
  {
    "id": "IAC-09",
    "name": "Terraform Network Security",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "cidr_blocks\\s*=\\s*\\[\\s*['\\\"]0\\.0\\.0\\.0/0['\\\"]\\s*\\]",
          "confidence": 0.85
        },
        {
          "type": "regex",
          "value": "from_port\\s*=\\s*(?:22|3389|6379|27017)",
          "confidence": 0.7
        }
      ]
    }
  },
  {
    "id": "IAC-10",
    "name": "Terraform IAM / Auth Security",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "Action\\s*=\\s*\\[?\\s*['\\\"]\\*['\\\"]",
          "confidence": 0.8
        },
        {
          "type": "regex",
          "value": "Effect\\s*=\\s*['\\\"]Allow['\\\"].*Principal\\s*=\\s*['\\\"]\\*['\\\"]",
          "confidence": 0.7
        }
      ]
    }
  },
  {
    "id": "IAC-11",
    "name": "Terraform General Security",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "backend\\s*\\\"local\\\"",
          "confidence": 0.7
        },
        {
          "type": "regex",
          "value": "required_version\\s*=.*['\\\"][<>=]",
          "confidence": 0.3
        }
      ]
    }
  },
  {
    "id": "IAC-12",
    "name": "Ansible Security",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "(?i)ansible_become_password",
          "confidence": 0.85
        },
        {
          "type": "regex",
          "value": "(?i)ansible_ssh_pass",
          "confidence": 0.85
        },
        {
          "type": "config_yaml",
          "value": "validate_certs:false",
          "confidence": 0.7
        }
      ]
    }
  },
  {
    "id": "IAC-13",
    "name": "Helm Chart Security",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "config_yaml",
          "value": "image.tag:latest",
          "confidence": 0.6
        }
      ]
    }
  },
  {
    "id": "IAC-14",
    "name": "CloudFormation / CDK Security",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "(?i)S3Bucket.*PublicRead|PublicReadWrite",
          "confidence": 0.8
        },
        {
          "type": "regex",
          "value": "(?i)CidrIp:\\s*0\\.0\\.0\\.0/0",
          "confidence": 0.7
        }
      ]
    }
  },
  {
    "id": "IAC-15",
    "name": "Serverless Framework / SAM Security",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "(?i)auth:\\s*NONE",
          "confidence": 0.7
        },
        {
          "type": "regex",
          "value": "(?i)iamRoleStatements:\\s*\\n.*Effect:\\s*Allow.*Action:\\s*\\*",
          "confidence": 0.7
        }
      ]
    }
  },
  {
    "id": "IAC-16",
    "name": "Pulumi / Multi-cloud IaC Security",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "(?i)encryptionSettings",
          "confidence": 0.4
        }
      ]
    }
  },
  {
    "id": "IAC-17",
    "name": "Serverless Function Security",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "(?i)lambda\\.FunctionUrl",
          "confidence": 0.6
        },
        {
          "type": "regex",
          "value": "(?i)lambda:\\*",
          "confidence": 0.5
        }
      ]
    }
  },
  {
    "id": "SEC-18",
    "name": "Authentication Missing",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "router\\.(?:get|post|put|delete|patch)\\s*\\(\\s*['\\\"][^'\\\"]*['\\\"]\\s*,",
          "confidence": 0.5
        }
      ]
    }
  },
  {
    "id": "SEC-22",
    "name": "IDOR (Insecure Direct Object Reference)",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "(?:router|app)\\.(?:get|post|put|delete|patch)\\s*\\(\\s*['\\\"][^'\\\"]*[:<]\\w+[>'\\\"]",
          "confidence": 0.5
        }
      ]
    }
  },
  {
    "id": "SEC-39",
    "name": "Dependency Confusion",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "[\"\\']@[a-z]+-[a-z]+[\"\\']\\s*:\\s*[\"\\'][\\^~]?\\d+\\.",
          "confidence": 0.5
        },
        {
          "type": "regex",
          "value": "[\"\\']@[a-z]+[-][a-z]+[\"\\']\\s*:",
          "confidence": 0.5
        },
        {
          "type": "regex",
          "value": "@\\w+-\\w+",
          "confidence": 0.45
        }
      ]
    }
  },
  {
    "id": "SEC-52",
    "name": "Log Injection",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": []
    }
  },
  {
    "id": "SEC-53",
    "name": "Integer Overflow / Wrap-Around",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "\\b\\w+\\s*-=\\s*\\w+",
          "confidence": 0.4
        }
      ]
    }
  },
  {
    "id": "SEC-54",
    "name": "Null Pointer Dereference",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "(?:orElse|nullof)|\\.get\\(\\)",
          "confidence": 0.35
        }
      ]
    }
  },
  {
    "id": "SEC-55",
    "name": "Sensitive Data Plaintext Storage",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": []
    }
  },
  {
    "id": "SEC-56",
    "name": "Weak Password Policy",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "(?i)min.*(?:length|len|size)\\s*[:=<>!]+\\s*[456]\\b",
          "confidence": 0.55
        }
      ]
    }
  },
  {
    "id": "SEC-57",
    "name": "Audit Log Missing",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "DELETE\\s+(?:FROM\\s+)?users?",
          "confidence": 0.45
        }
      ]
    }
  },
  {
    "id": "SEC-58",
    "name": "Brute Force Protection Missing",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": []
    }
  },
  {
    "id": "SEC-59",
    "name": "Incomplete Data Deletion / Residual Data",
    "rule_type": "code_review",
    "applicable_stages": [
      "batch"
    ],
    "target_files": [
      "**/*"
    ],
    "detection_method": "regex",
    "fp_risk": "medium",
    "performance": "high",
    "priority": 3,
    "detection": {
      "mode": "any",
      "patterns": [
        {
          "type": "regex",
          "value": "(?i)is_deleted\\s*=|deleted_flag|deleted_at\\s*=",
          "confidence": 0.45
        }
      ]
    }
  }
]
