## ADDED Requirements

### Requirement: Modern responsive tool presentation
The browser demo SHALL present AES, RSA, SHA-256, and legacy MD5 as visually distinct, responsive tool sections with a consistent modern form layout at narrow and wide viewport sizes.

#### Scenario: Visitor views the page
- **WHEN** a visitor opens the demo
- **THEN** the page SHALL show a clear explanation that cryptographic processing happens in the browser and SHALL present the available tools without requiring horizontal scrolling at a narrow viewport

#### Scenario: Visitor scans the available tools
- **WHEN** the demo finishes loading
- **THEN** every tool section SHALL be expanded and its summary SHALL identify the capability it contains

### Requirement: Accessible interactive controls
The browser demo SHALL give each interactive control an accessible name, visible keyboard focus treatment, and a concise mouseover title, and SHALL retain semantic labels for every input.

#### Scenario: Keyboard user operates a tool
- **WHEN** a keyboard user tabs through a tool section
- **THEN** every action and value control SHALL be reachable with a visible focus indication and identifiable without relying on iconography or colour alone

#### Scenario: Visitor uses a value-export control
- **WHEN** a visitor views a copy or download button
- **THEN** its icon SHALL use a complete view box and fit within its button with visible padding on every supported viewport

### Requirement: Safe primary AES experience
The browser demo SHALL retain GCM as the selected AES mode on initial load and SHALL explain the selected mode's parameter storage requirement beside the AES controls.

#### Scenario: Visitor opens the AES tool
- **WHEN** a visitor views the initially expanded AES section
- **THEN** GCM SHALL be selected and the page SHALL explain that the generated nonce must be saved with the ciphertext

### Requirement: Guided local action flows
The browser demo SHALL place each transformation action between or immediately beside the fields it reads and writes, and SHALL keep feedback in the same tool section as the action.

#### Scenario: Visitor uses a text transformation
- **WHEN** a visitor views AES encryption, AES decryption, RSA encryption, RSA decryption, signing, or verification controls
- **THEN** the relevant action controls SHALL visually connect their source and result fields

#### Scenario: Visitor receives AES text feedback
- **WHEN** a visitor encrypts text
- **THEN** the AES status message SHALL appear above the unencrypted-text field
- **WHEN** a visitor decrypts text
- **THEN** the AES status message SHALL appear above the encrypted-text field

#### Scenario: Visitor generates RSA keys
- **WHEN** a visitor starts or completes RSA key generation
- **THEN** its status message SHALL appear alongside the key-generation controls

#### Scenario: Another action happens during an asynchronous operation
- **WHEN** an asynchronous action completes after the visitor starts a different action
- **THEN** the completed action's feedback SHALL remain at the original action's feedback region

#### Scenario: Visitor needs AES-GCM inputs
- **WHEN** a visitor views the AES-GCM flow
- **THEN** the page SHALL explain that the key is needed for both encryption and decryption and that the generated nonce must be saved with ciphertext and supplied to decrypt it later

### Requirement: Field-specific failure feedback
The browser demo SHALL show an actionable status message in the tool section that initiated an action and SHALL visually mark every known missing or invalid field that prevented the requested action.

#### Scenario: Visitor decrypts without a key
- **WHEN** a visitor requests AES decryption without a valid 32-character key
- **THEN** the AES section SHALL report the missing key beside its controls and SHALL mark the key field invalid until the visitor changes it

#### Scenario: Visitor completes a replacement AES action
- **WHEN** a visitor successfully encrypts or decrypts after a failed AES action
- **THEN** the AES section SHALL clear invalid styling from every AES text field whose prior error is superseded by that successful transformation

#### Scenario: Visitor starts encryption after failed decryption
- **WHEN** a visitor begins AES encryption after an AES decryption failure
- **THEN** the AES section SHALL clear the superseded decryption feedback and invalid styling before reporting the encryption result, whether encryption succeeds or fails

#### Scenario: Visitor cannot encrypt a selected file
- **WHEN** local file encryption cannot complete
- **THEN** the AES section SHALL explain that the selected file was not changed and give a specific recovery action without exposing the file contents

### Requirement: Single-flight key generation
The browser demo SHALL prevent overlapping RSA key-generation requests.

#### Scenario: Visitor generates an RSA key pair
- **WHEN** RSA key generation is in progress
- **THEN** the generate control and key-size selector SHALL be disabled, subsequent invocations SHALL be ignored, and both controls SHALL be restored when generation finishes or fails

### Requirement: Local-only working state
The browser demo SHALL keep entered, generated, and derived values only in the live document unless the user explicitly copies a value or downloads a file or key.

#### Scenario: Visitor refreshes the demo
- **WHEN** a visitor enters or generates values and then refreshes, closes, or navigates away from the page
- **THEN** the demo SHALL not restore those values from cookies, localStorage, sessionStorage, IndexedDB, or another browser persistence mechanism

#### Scenario: The demo initializer is invoked after the page is ready
- **WHEN** the live document already contains entered values and the demo initializer runs again
- **THEN** the initializer SHALL leave the existing document and values intact without duplicating the demo

#### Scenario: Visitor performs a crypto action
- **WHEN** a visitor hashes, encrypts, decrypts, signs, verifies, or generates a key
- **THEN** the demo SHALL process the value locally and SHALL not transmit it over the network
