// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// GENERATED from the three *.schema.json files beside it (KYA-OS story F-1) so the
// published package carries the schemas without a JSON import. Regenerate with
// `node scripts/sync-credential-schemas.mjs`; tests/unit/core/credentials/schemas.test.ts
// fails when the two drift. Do not hand-edit.

import type { JsonSchema } from "../credentials/json-schema.js";

/** `src/core/schemas/identity-credential.schema.json` */
export const IDENTITY_CREDENTIAL_SCHEMA: JsonSchema = {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://helixid.io/schemas/kya-os/identity-credential/v1",
  "title": "Helix Agent Identity Credential",
  "description": "KYA-OS story F-1: the agent's identity, issued by Helix. Agent DID, display name and the owner DID as responsibleParty. It carries no scopes: capability attestations do. Reissued only on key rotation or offboarding.",
  "type": "object",
  "required": [
    "@context",
    "id",
    "type",
    "issuer",
    "validFrom",
    "credentialSubject",
    "credentialStatus",
    "proof"
  ],
  "properties": {
    "@context": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "string"
      },
      "contains": {
        "const": "https://www.w3.org/ns/credentials/v2"
      }
    },
    "id": {
      "type": "string",
      "minLength": 1
    },
    "type": {
      "type": "array",
      "minItems": 2,
      "items": {
        "type": "string"
      },
      "allOf": [
        {
          "contains": {
            "const": "VerifiableCredential"
          }
        },
        {
          "contains": {
            "const": "AgentIdentityCredential"
          }
        }
      ]
    },
    "issuer": {
      "type": "string",
      "pattern": "^did:.+$"
    },
    "validFrom": {
      "type": "string",
      "format": "date-time"
    },
    "validUntil": {
      "type": "string",
      "format": "date-time"
    },
    "credentialSubject": {
      "type": "object",
      "required": [
        "id",
        "name",
        "responsibleParty"
      ],
      "properties": {
        "id": {
          "type": "string",
          "pattern": "^did:.+$"
        },
        "name": {
          "type": "string",
          "minLength": 1
        },
        "responsibleParty": {
          "type": "string",
          "pattern": "^did:.+$"
        }
      },
      "additionalProperties": false
    },
    "credentialStatus": {
      "$ref": "#/$defs/BitstringStatusListEntry"
    },
    "proof": {
      "$ref": "#/$defs/DataIntegrityProof"
    }
  },
  "additionalProperties": false,
  "$defs": {
    "BitstringStatusListEntry": {
      "type": "object",
      "required": [
        "type",
        "statusPurpose",
        "statusListIndex",
        "statusListCredential"
      ],
      "properties": {
        "id": {
          "type": "string"
        },
        "type": {
          "const": "BitstringStatusListEntry"
        },
        "statusPurpose": {
          "enum": [
            "revocation",
            "suspension"
          ]
        },
        "statusListIndex": {
          "type": "string",
          "pattern": "^[0-9]+$"
        },
        "statusListCredential": {
          "type": "string",
          "minLength": 1
        },
        "statusSize": {
          "type": "integer"
        }
      },
      "additionalProperties": false
    },
    "DataIntegrityProof": {
      "type": "object",
      "required": [
        "type",
        "cryptosuite",
        "created",
        "verificationMethod",
        "proofPurpose",
        "proofValue"
      ],
      "properties": {
        "type": {
          "const": "DataIntegrityProof"
        },
        "cryptosuite": {
          "const": "eddsa-jcs-2022"
        },
        "created": {
          "type": "string",
          "format": "date-time"
        },
        "verificationMethod": {
          "type": "string",
          "pattern": "^did:.+#.+$"
        },
        "proofPurpose": {
          "const": "assertionMethod"
        },
        "proofValue": {
          "type": "string",
          "pattern": "^z[1-9A-HJ-NP-Za-km-z]+$"
        }
      },
      "additionalProperties": false
    }
  }
} as const;

/** `src/core/schemas/capability-attestation.schema.json` */
export const CAPABILITY_ATTESTATION_SCHEMA: JsonSchema = {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://helixid.io/schemas/kya-os/capability-attestation/v1",
  "title": "KYA-OS Capability Attestation Credential",
  "description": "KYA-OS story F-1 / C-B: one CapabilityAttestationCredential per capability (scope). credentialSubject.id is the agent DID (the card id), capability is the name a card's capabilities entry carries, validUntil bounds it, and a Bitstring status entry revokes it. Signed by the owner through the SDK or by the Helix issuer.",
  "type": "object",
  "required": [
    "@context",
    "id",
    "type",
    "issuer",
    "validFrom",
    "validUntil",
    "credentialSubject",
    "credentialStatus",
    "proof"
  ],
  "properties": {
    "@context": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "string"
      },
      "contains": {
        "const": "https://www.w3.org/ns/credentials/v2"
      }
    },
    "id": {
      "type": "string",
      "minLength": 1
    },
    "type": {
      "type": "array",
      "minItems": 2,
      "items": {
        "type": "string"
      },
      "allOf": [
        {
          "contains": {
            "const": "VerifiableCredential"
          }
        },
        {
          "contains": {
            "const": "CapabilityAttestationCredential"
          }
        }
      ]
    },
    "issuer": {
      "type": "string",
      "pattern": "^did:.+$"
    },
    "validFrom": {
      "type": "string",
      "format": "date-time"
    },
    "validUntil": {
      "type": "string",
      "format": "date-time"
    },
    "credentialSubject": {
      "type": "object",
      "required": [
        "id",
        "capability"
      ],
      "properties": {
        "id": {
          "type": "string",
          "pattern": "^did:.+$"
        },
        "capability": {
          "type": "string",
          "minLength": 1
        }
      },
      "additionalProperties": false
    },
    "credentialStatus": {
      "$ref": "#/$defs/BitstringStatusListEntry"
    },
    "proof": {
      "$ref": "#/$defs/DataIntegrityProof"
    }
  },
  "additionalProperties": false,
  "$defs": {
    "BitstringStatusListEntry": {
      "type": "object",
      "required": [
        "type",
        "statusPurpose",
        "statusListIndex",
        "statusListCredential"
      ],
      "properties": {
        "id": {
          "type": "string"
        },
        "type": {
          "const": "BitstringStatusListEntry"
        },
        "statusPurpose": {
          "enum": [
            "revocation",
            "suspension"
          ]
        },
        "statusListIndex": {
          "type": "string",
          "pattern": "^[0-9]+$"
        },
        "statusListCredential": {
          "type": "string",
          "minLength": 1
        },
        "statusSize": {
          "type": "integer"
        }
      },
      "additionalProperties": false
    },
    "DataIntegrityProof": {
      "type": "object",
      "required": [
        "type",
        "cryptosuite",
        "created",
        "verificationMethod",
        "proofPurpose",
        "proofValue"
      ],
      "properties": {
        "type": {
          "const": "DataIntegrityProof"
        },
        "cryptosuite": {
          "const": "eddsa-jcs-2022"
        },
        "created": {
          "type": "string",
          "format": "date-time"
        },
        "verificationMethod": {
          "type": "string",
          "pattern": "^did:.+#.+$"
        },
        "proofPurpose": {
          "const": "assertionMethod"
        },
        "proofValue": {
          "type": "string",
          "pattern": "^z[1-9A-HJ-NP-Za-km-z]+$"
        }
      },
      "additionalProperties": false
    }
  }
} as const;

/** `src/core/schemas/delegation-hop.schema.json` */
export const DELEGATION_HOP_SCHEMA: JsonSchema = {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://helixid.io/schemas/kya-os/delegation-hop/v1",
  "title": "KYA-OS Delegation Credential (one hop), Helix profile",
  "description": "KYA-OS SPEC.md section 6.10: a W3C VC 2.0 whose credentialSubject IS an attenuated ZCAP-LD capability, one credential per delegation hop, revoked through a Bitstring Status List entry and signed with a DataIntegrityProof eddsa-jcs-2022. This profile of schemas/card-delegation-credential.json (suite 1.10.0) closes the credentialSubject: a member it does not name is refused, the Core L3.5a rule against claim-contaminated subjects, and requires validUntil on every hop.",
  "type": "object",
  "required": [
    "@context",
    "id",
    "type",
    "issuer",
    "validUntil",
    "credentialSubject",
    "credentialStatus",
    "proof"
  ],
  "properties": {
    "@context": {
      "type": "array",
      "minItems": 3,
      "items": {
        "type": "string"
      },
      "allOf": [
        {
          "contains": {
            "const": "https://www.w3.org/ns/credentials/v2"
          }
        },
        {
          "contains": {
            "const": "https://w3id.org/security/zcap/v1"
          }
        },
        {
          "contains": {
            "const": "https://kya-os.org/ns/delegation/v1"
          }
        }
      ]
    },
    "id": {
      "type": "string",
      "minLength": 1
    },
    "type": {
      "type": "array",
      "minItems": 2,
      "items": {
        "type": "string"
      },
      "allOf": [
        {
          "contains": {
            "const": "VerifiableCredential"
          }
        },
        {
          "contains": {
            "const": "DelegationCredential"
          }
        }
      ]
    },
    "issuer": {
      "type": "string",
      "pattern": "^did:.+$"
    },
    "validFrom": {
      "type": "string",
      "format": "date-time"
    },
    "validUntil": {
      "type": "string",
      "format": "date-time"
    },
    "credentialSubject": {
      "$ref": "#/$defs/ZcapCapability"
    },
    "credentialStatus": {
      "$ref": "#/$defs/BitstringStatusListEntry"
    },
    "proof": {
      "$ref": "#/$defs/DataIntegrityProof"
    }
  },
  "additionalProperties": false,
  "$defs": {
    "ZcapCapability": {
      "type": "object",
      "required": [
        "id",
        "parentCapability",
        "invocationTarget",
        "allowedAction"
      ],
      "anyOf": [
        {
          "required": [
            "invoker"
          ]
        },
        {
          "required": [
            "controller"
          ]
        }
      ],
      "properties": {
        "id": {
          "type": "string",
          "minLength": 1
        },
        "invoker": {
          "type": "string",
          "pattern": "^did:.+$"
        },
        "controller": {
          "type": "string",
          "pattern": "^did:.+$"
        },
        "parentCapability": {
          "type": "string",
          "minLength": 1
        },
        "invocationTarget": {
          "type": "string",
          "minLength": 1
        },
        "allowedAction": {
          "type": "array",
          "items": {
            "type": "string",
            "minLength": 1
          }
        },
        "caveats": {
          "type": "array",
          "items": {
            "$ref": "#/$defs/Caveat"
          }
        }
      },
      "additionalProperties": false
    },
    "Caveat": {
      "type": "object",
      "required": [
        "type"
      ],
      "properties": {
        "type": {
          "type": "string",
          "minLength": 1
        },
        "date": {
          "type": "string",
          "format": "date-time"
        },
        "limit": {
          "type": "string",
          "pattern": "^[0-9]+(\\.[0-9]+)?$"
        },
        "currency": {
          "type": "string",
          "minLength": 1
        }
      },
      "additionalProperties": true
    },
    "BitstringStatusListEntry": {
      "type": "object",
      "required": [
        "type",
        "statusPurpose",
        "statusListIndex",
        "statusListCredential"
      ],
      "properties": {
        "id": {
          "type": "string"
        },
        "type": {
          "const": "BitstringStatusListEntry"
        },
        "statusPurpose": {
          "enum": [
            "revocation",
            "suspension"
          ]
        },
        "statusListIndex": {
          "type": "string",
          "pattern": "^[0-9]+$"
        },
        "statusListCredential": {
          "type": "string",
          "minLength": 1
        },
        "statusSize": {
          "type": "integer"
        }
      },
      "additionalProperties": false
    },
    "DataIntegrityProof": {
      "type": "object",
      "required": [
        "type",
        "cryptosuite",
        "created",
        "verificationMethod",
        "proofPurpose",
        "proofValue"
      ],
      "properties": {
        "type": {
          "const": "DataIntegrityProof"
        },
        "cryptosuite": {
          "const": "eddsa-jcs-2022"
        },
        "created": {
          "type": "string",
          "format": "date-time"
        },
        "verificationMethod": {
          "type": "string",
          "pattern": "^did:.+#.+$"
        },
        "proofPurpose": {
          "const": "assertionMethod"
        },
        "proofValue": {
          "type": "string",
          "pattern": "^z[1-9A-HJ-NP-Za-km-z]+$"
        }
      },
      "additionalProperties": false
    }
  }
} as const;

