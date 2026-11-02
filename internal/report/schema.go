package report

const SchemaVersion = "1.0.0"

const FindingsJSONSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://github.com/joeyvictorino/tasia/blob/main/docs/findings-schema.json",
  "title": "Tasia Findings Report",
  "description": "Output of tasia review --format json or tasia ci --format json. Each report contains a decision, a risk level and zero or more deterministic findings.",
  "type": "object",
  "required": ["schema_version", "decision", "risk", "findings"],
  "additionalProperties": false,
  "properties": {
    "schema_version": {
      "type": "string",
      "description": "Semantic version of this schema (MAJOR.MINOR.PATCH). A MAJOR bump means a breaking change to the shape; MINOR adds fields; PATCH changes descriptions only.",
      "pattern": "^[0-9]+\\.[0-9]+\\.[0-9]+$",
      "examples": ["1.0.0"]
    },
    "decision": {
      "type": "string",
      "enum": ["PASS", "BLOCKED", "ERROR"],
      "description": "PASS when no finding meets the fail-on threshold, BLOCKED when at least one does, ERROR when a config file could not be parsed (fail-closed)."
    },
    "risk": {
      "type": "string",
      "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"],
      "description": "The highest severity among all findings, or UNKNOWN on parse error."
    },
    "findings": {
      "type": "array",
      "description": "Zero or more deterministic findings, each with stable fields. Empty array when no rule matched.",
      "items": { "$ref": "#/$defs/finding" }
    },
    "parse_errors": {
      "type": "array",
      "description": "Present only when decision is ERROR. Lists files that could not be parsed.",
      "items": { "$ref": "#/$defs/parse_error" }
    }
  },
  "$defs": {
    "finding": {
      "type": "object",
      "required": ["id", "severity", "title", "file", "line", "evidence", "why", "fix"],
      "additionalProperties": false,
      "properties": {
        "id": {
          "type": "string",
          "description": "Stable rule identifier (e.g. exposed_inference, kube_privileged). Use this for .tasiaignore entries and severity overrides.",
          "pattern": "^[a-z][a-z0-9_]*$"
        },
        "severity": {
          "type": "string",
          "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
          "description": "Severity after any .tasiarc.yaml overrides have been applied."
        },
        "title": {
          "type": "string",
          "description": "One-line human-readable summary of the finding."
        },
        "file": {
          "type": "string",
          "description": "Path to the file where the finding was detected, relative to the scanned directory."
        },
        "line": {
          "type": "integer",
          "minimum": 0,
          "description": "1-based line number in the file. 0 means the finding applies to the file as a whole."
        },
        "evidence": {
          "type": "string",
          "description": "Machine-readable key=value evidence string. Never contains secret values."
        },
        "why": {
          "type": "string",
          "description": "Explanation of why this matters for security."
        },
        "fix": {
          "type": "string",
          "description": "Recommended remediation."
        }
      }
    },
    "parse_error": {
      "type": "object",
      "required": ["path", "error"],
      "additionalProperties": false,
      "properties": {
        "path": {
          "type": "string",
          "description": "Path to the file that could not be parsed."
        },
        "error": {
          "type": "string",
          "description": "Human-readable error message."
        }
      }
    }
  }
}`
