## Purpose

Enforce appliance boot ordering, default-deny network policy and measured service confinement while publishing only the intended persistent host settings.

## ADDED Requirements

### Requirement: KMS-HOST-001 Require AppArmor before KMS startup

The appliance's KMS service SHALL require the named AppArmor profile and refuse start if AppArmor cannot confine it. Host-local settings SHALL NOT replace that requirement.

#### Scenario: AppArmor disabled or its named profile unavailable
- **WHEN** systemd attempts starting the appliance KMS service
- **THEN** the unit does not permit an unconfined start.

### Requirement: KMS-HOST-002 Default-deny appliance network traffic

The base input, forwarding and output firewall chains SHALL default to drop. Allowed service traffic SHALL be limited to declared zones and destinations.

#### Scenario: A peer address is outside the configured zone
- **WHEN** the renderer creates rules for an enabled service
- **THEN** the service rule permits the declared zone only, with all other packets subject to default drop.

### Requirement: KMS-HOST-003 Build factory configuration before consuming it

The appliance SHALL populate transient /etc from the factory image before sysusers, general tmpfiles and AppArmor use it. Persistent per-host settings SHALL appear only at their approved paths.

#### Scenario: Boot starts with a fresh /etc
- **WHEN** the factory unit runs during early boot
- **THEN** the image copy precedes its consumers and persistent links are limited to the declared inventory.

### Requirement: KMS-HOST-004 Order TEST staging network consumption after publication

With the TEST staging boot flag and its per-host file present, networkd SHALL wait until tmpfiles has installed the network configuration link. Both TEST eligibility conditions SHALL remain required.

#### Scenario: Staging link is not yet present at boot
- **WHEN** tmpfiles is scheduled later than networkd would otherwise read configuration
- **THEN** networkd waits for tmpfiles on the guarded staging path.

### Requirement: KMS-HOST-005 Run appliance KMS under its service identity

The appliance KMS unit SHALL use a dedicated non-root account and SHALL request the installed KMS AppArmor profile.

#### Scenario: The appliance KMS unit selects its account and profile
- **WHEN** systemd selects the installed appliance KMS unit
- **THEN** its effective configuration names the dedicated non-root KMS account and requires its AppArmor profile.

#### Scenario: The appliance composes the common KMS unit with image and credential settings

- **WHEN** the shipped appliance loads the common unit and its image drop-ins and runs its host credential generator
- **THEN** the unit retains the same account and configuration path, requests the named AppArmor profile and firewall startup checks, and receives generated encrypted PIN mappings only for accepted blobs in the host's persistent store. The generator adds no mappings when it finds none
