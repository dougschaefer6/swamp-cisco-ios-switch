import type { AccessPortRange, CiscoIosGlobalArgs, Vlan } from "./_ssh.ts";

/**
 * Pure IOS config-line generators and output sanitizers for the
 * `@dougschaefer/cisco-ios-switch` model. These have no I/O and no Deno
 * dependencies, so they are unit-tested directly and shared by the model's
 * dry-run and live paths.
 */

/** Secure-access hardening lines asserted idempotently by `applyBaseline`. */
export function baselineLines(g: CiscoIosGlobalArgs): string[] {
  const lines: string[] = [];
  if (g.hostname) lines.push(`hostname ${g.hostname}`);
  if (g.domainName) lines.push(`ip domain-name ${g.domainName}`);
  lines.push(
    "service password-encryption",
    "no ip http server",
    "no ip http secure-server",
    "ip ssh version 2",
    "line console 0",
    " logging synchronous",
    " exec-timeout 15 0",
    " login local",
    "exit",
    "line vty 0 15",
    " exec-timeout 15 0",
    " logging synchronous",
    " login local",
    " transport input ssh",
    "exit",
  );
  return lines;
}

/** SNMPv2c lines from `globalArguments.snmp`. */
export function snmpLines(g: CiscoIosGlobalArgs): string[] {
  const s = g.snmp!;
  const lines: string[] = [];
  if (s.readOnly) lines.push(`snmp-server community ${s.readOnly} RO`);
  if (s.readWrite) lines.push(`snmp-server community ${s.readWrite} RW`);
  if (s.location) lines.push(`snmp-server location ${s.location}`);
  if (s.contact) lines.push(`snmp-server contact ${s.contact}`);
  if (s.trapHost && s.readOnly) {
    lines.push(`snmp-server host ${s.trapHost} version 2c ${s.readOnly}`);
    lines.push("snmp-server enable traps");
  }
  return lines;
}

/** Layer-3 / VLAN lines from `globalArguments.routing`. */
export function routingLines(g: CiscoIosGlobalArgs): string[] {
  const r = g.routing!;
  const lines: string[] = [];
  if (r.enabled) lines.push("ip routing");
  for (const v of r.vlans as Vlan[]) {
    lines.push(`vlan ${v.id}`, ` name ${v.name}`, "exit");
    if (v.sviIp && v.sviMask) {
      lines.push(
        `interface vlan ${v.id}`,
        ` description ${v.name} gateway`,
        ` ip address ${v.sviIp} ${v.sviMask}`,
        " no shutdown",
        "exit",
      );
    }
  }
  if (r.enabled && r.defaultRouteNextHop) {
    lines.push(`ip route 0.0.0.0 0.0.0.0 ${r.defaultRouteNextHop}`);
  }
  for (const p of r.accessPorts as AccessPortRange[]) {
    lines.push(`interface range ${p.range}`);
    if (p.description) lines.push(` description ${p.description}`);
    lines.push(
      " switchport mode access",
      ` switchport access vlan ${p.vlanId}`,
    );
    if (p.portfast) lines.push(" spanning-tree portfast");
    lines.push("exit");
  }
  return lines;
}

/** Parse hostname/model/IOS version/uptime out of `show version`. */
export function parseShowVersion(text: string): {
  hostname: string;
  model: string;
  iosVersion: string;
  uptime: string;
} {
  const uptimeMatch = text.match(/^(\S+)\s+uptime is\s+(.+)$/m);
  const versionMatch = text.match(/Version\s+([^\s,]+)/);
  const modelMatch = text.match(
    /(?:Model number\s*:\s*|cisco\s+)(\S*2960\S*|WS-\S+|C9\S+)/i,
  );
  return {
    hostname: uptimeMatch?.[1]?.trim() ?? "",
    model: modelMatch?.[1]?.trim() ?? "",
    iosVersion: versionMatch?.[1]?.trim() ?? "",
    uptime: uptimeMatch?.[2]?.trim() ?? "",
  };
}

/** Replace community/secret/password/key values on a single config line. */
export function redactLine(line: string): string {
  return line
    .replace(/(snmp-server community\s+)(\S+)/i, "$1<redacted>")
    .replace(
      /(snmp-server host\s+\S+\s+version\s+\S+\s+)(\S+)/i,
      "$1<redacted>",
    )
    // secret/password values can be "type hash" (e.g. "5 $1$..") — redact to EOL.
    .replace(/(\bsecret\s+)(.+)$/i, "$1<redacted>")
    .replace(/(\bpassword\s+)(.+)$/i, "$1<redacted>")
    .replace(/(\bkey\s+)(\d.*)$/i, "$1<redacted>");
}

/** Strip secret-bearing lines from a running-config before storage. */
export function redactConfig(config: string): string {
  return config
    .split(/\r?\n/)
    .map((l) =>
      /^\s*(snmp-server community|enable (secret|password)|username .* (secret|password)|.*\bpassword\b|key\s+\d)/i
          .test(l)
        ? redactLine(l)
        : l
    )
    .join("\n");
}
