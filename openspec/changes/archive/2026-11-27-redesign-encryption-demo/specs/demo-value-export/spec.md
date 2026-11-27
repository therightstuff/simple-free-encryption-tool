## ADDED Requirements

### Requirement: Explicit value copying
The browser demo SHALL provide a copy action beside every readable or editable text value and displayed verification result. Each copy action SHALL use a standard copy icon, an accessible name, and a title that identifies the value to copy.

#### Scenario: Visitor copies a generated result
- **WHEN** a visitor activates the copy action for a non-empty result value
- **THEN** the demo SHALL copy the current displayed value only after that activation and SHALL give local success feedback without echoing the value

#### Scenario: Clipboard write cannot complete
- **WHEN** a visitor activates a copy action and the browser cannot copy the current value
- **THEN** the demo SHALL retain the value, report that the requested copy did not complete, and leave the value available for manual selection

### Requirement: Explicit RSA PEM downloads
The browser demo SHALL provide separate save-icon download actions next to the public and private RSA key fields. A download action SHALL use the current non-empty field value as UTF-8 text and SHALL have an accessible name and title that identify the key type.

#### Scenario: Visitor downloads a generated public key
- **WHEN** a visitor activates the public-key download action for a non-empty public-key field
- **THEN** the browser SHALL receive a download named `sfet-public-key.pem` containing only that field's current PEM text

#### Scenario: Visitor downloads a generated private key
- **WHEN** a visitor activates the private-key download action for a non-empty private-key field
- **THEN** the browser SHALL receive a download named `sfet-private-key.pem` containing only that field's current PEM text

#### Scenario: RSA key field is empty
- **WHEN** the corresponding RSA PEM field is empty
- **THEN** its download action SHALL not initiate a download

### Requirement: No implicit export or persistence
The browser demo SHALL not copy, download, store, or transmit a user value until the user explicitly invokes the corresponding action.

#### Scenario: Visitor generates RSA keys
- **WHEN** a visitor generates an RSA key pair
- **THEN** the demo SHALL display the generated values without copying, downloading, or persistently storing either key
