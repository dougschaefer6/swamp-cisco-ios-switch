import { assert, assertEquals } from "jsr:@std/assert@1";
import {
  baselineLines,
  parseShowVersion,
  redactConfig,
  redactLine,
  routingLines,
  snmpLines,
} from "./_config.ts";
import { type CiscoIosGlobalArgs, findIosError } from "./_ssh.ts";

/** Build a CiscoIosGlobalArgs for line-generator tests (only the read fields matter). */
function args(partial: Partial<CiscoIosGlobalArgs>): CiscoIosGlobalArgs {
  return {
    host: "192.0.2.10",
    port: 22,
    username: "admin",
    password: "x",
    legacyAlgorithms: true,
    commandTimeoutMs: 20000,
    ...partial,
  } as CiscoIosGlobalArgs;
}

Deno.test("baselineLines includes hostname/domain when set and SSH-only VTY", () => {
  const lines = baselineLines(args({ hostname: "SW-1", domainName: "corp.example.com" }));
  assert(lines.includes("hostname SW-1"));
  assert(lines.includes("ip domain-name corp.example.com"));
  assert(lines.includes(" transport input ssh"));
  assert(lines.includes(" login local"));
  assert(lines.includes("no ip http server"));
});

Deno.test("baselineLines omits hostname/domain when unset", () => {
  const lines = baselineLines(args({}));
  assert(!lines.some((l) => l.startsWith("hostname ")));
  assert(!lines.some((l) => l.startsWith("ip domain-name ")));
  assert(lines.includes("service password-encryption"));
});

Deno.test("snmpLines emits RO/RW/location/contact and trap host", () => {
  const lines = snmpLines(args({
    snmp: {
      readOnly: "RO_STR",
      readWrite: "RW_STR",
      location: "Core IDF",
      contact: "noc@example.com",
      trapHost: "192.0.2.50",
    },
  }));
  assertEquals(lines, [
    "snmp-server community RO_STR RO",
    "snmp-server community RW_STR RW",
    "snmp-server location Core IDF",
    "snmp-server contact noc@example.com",
    "snmp-server host 192.0.2.50 version 2c RO_STR",
    "snmp-server enable traps",
  ]);
});

Deno.test("snmpLines skips trap host when no read-only community", () => {
  const lines = snmpLines(args({ snmp: { readWrite: "RW", trapHost: "192.0.2.50" } }));
  assert(!lines.some((l) => l.startsWith("snmp-server host")));
  assert(!lines.includes("snmp-server enable traps"));
});

Deno.test("routingLines builds VLANs, SVI, default route, and access ports", () => {
  const lines = routingLines(args({
    routing: {
      enabled: true,
      defaultRouteNextHop: "192.0.2.1",
      vlans: [
        { id: 20, name: "USER", sviIp: "198.51.100.1", sviMask: "255.255.255.0" },
        { id: 30, name: "AV" }, // L2-only, no SVI
      ],
      accessPorts: [
        { range: "gigabitEthernet 1/0/1 - 12", vlanId: 20, description: "Users", portfast: true },
      ],
    },
  }));
  assertEquals(lines[0], "ip routing");
  assert(lines.includes("interface vlan 20"));
  assert(lines.includes(" ip address 198.51.100.1 255.255.255.0"));
  // VLAN 30 created but no SVI
  assert(lines.includes("vlan 30"));
  assert(!lines.includes("interface vlan 30"));
  assert(lines.includes("ip route 0.0.0.0 0.0.0.0 192.0.2.1"));
  assert(lines.includes("interface range gigabitEthernet 1/0/1 - 12"));
  assert(lines.includes(" switchport access vlan 20"));
  assert(lines.includes(" spanning-tree portfast"));
});

Deno.test("routingLines omits ip routing and default route when disabled", () => {
  const lines = routingLines(args({
    routing: {
      enabled: false,
      defaultRouteNextHop: "192.0.2.1",
      vlans: [{ id: 40, name: "MGMT" }],
      accessPorts: [],
    },
  }));
  assert(!lines.includes("ip routing"));
  assert(!lines.some((l) => l.startsWith("ip route ")));
  assert(lines.includes("vlan 40"));
});

Deno.test("redactLine masks community, secret, password, and key values", () => {
  assertEquals(redactLine("snmp-server community S3cret RW"), "snmp-server community <redacted> RW");
  assertEquals(redactLine("enable secret 5 $1$abc"), "enable secret <redacted>");
  assert(redactLine("username admin password 0 Hunter2").includes("<redacted>"));
  assert(redactLine(" key 7 070C285F").includes("<redacted>"));
});

Deno.test("redactConfig masks secret-bearing lines, keeps others", () => {
  const cfg = [
    "hostname SW-1",
    "enable secret 5 $1$xyz",
    "snmp-server community PUBLIC RO",
    "interface Vlan1",
    " ip address 192.0.2.10 255.255.255.0",
  ].join("\n");
  const out = redactConfig(cfg);
  assert(out.includes("hostname SW-1"));
  assert(out.includes(" ip address 192.0.2.10 255.255.255.0"));
  assert(!out.includes("$1$xyz"));
  assert(!out.includes("PUBLIC"));
});

Deno.test("parseShowVersion extracts hostname, version, model, uptime", () => {
  const sample = [
    "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)",
    "SW-CORE uptime is 12 weeks, 3 days, 4 hours, 5 minutes",
    "System returned to ROM by power-on",
    "Model number                     : WS-C2960-24TT-L",
  ].join("\n");
  const f = parseShowVersion(sample);
  assertEquals(f.hostname, "SW-CORE");
  assertEquals(f.iosVersion, "15.0(2)SE11");
  assertEquals(f.uptime, "12 weeks, 3 days, 4 hours, 5 minutes");
  assert(f.model.includes("2960"));
});

Deno.test("findIosError catches IOS rejections but not syslog or clean output", () => {
  assert(findIosError("% Invalid input detected at '^' marker.") !== null);
  assert(findIosError("% Incomplete command.") !== null);
  assert(findIosError("vlan 20\n name USER\nSW-1(config)#") === null);
  // Syslog lines start with a facility token, not an error keyword.
  assertEquals(findIosError("%SYS-5-CONFIG_I: Configured from console by vty0"), null);
});
