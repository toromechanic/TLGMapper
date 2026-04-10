"""
TLGMapper.py — TraceLogging provider/event resolver for IDA Pro

Parses TraceLogging metadata embedded in x64 PE binaries and links
each event to its owning ETW provider and the function that (likely) fires it.

Two-stage approach:
  Stage A — Locate the ETW0 metadata header and sequentially parse all
            provider/event blobs (Type 2/4 providers, Type 3/5/6 events).
  Stage B — Walk functions via DataRefsFrom, match references against
            known metadata address ranges, and resolve provider ownership
            per event using instruction proximity and call-graph analysis.

Resolution priority chain:
  1. SingleProvider       — Binary contains only one provider
  2. Direct-Preceding     — Provider ref appears before the event ref in the same function
  3. Direct-Nearest       — Closest provider ref by address in the same function
  4. CallGraph-dN         — DFS through callees (max depth: 3), searching backward first
  5. Unknown              — No provider could be resolved

Results are displayed in IDA chooser windows. Batch mode writes CSV.

Usage (GUI):  File > Script file > TLGMapper.py
Usage (batch): ida64.exe -A -o"C:\\output\\<binary>.i64" -S"TLGMapper.py C:\\output" -LC:\\output\\log.txt <binary>
"""

import idaapi
import idautils
import ida_funcs
import ida_bytes
import ida_segment
import ida_nalt
import ida_kernwin
import ida_auto
import idc
import struct
import csv
import os
import traceback

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TLGIN_NAMES = {
    0: "NULL", 1: "UnicodeString", 2: "AnsiString", 3: "Int8", 4: "UInt8",
    5: "Int16", 6: "UInt16", 7: "Int32", 8: "UInt32", 9: "Int64",
    10: "UInt64", 11: "Float", 12: "Double", 13: "Bool32", 14: "Binary",
    15: "GUID", 16: "Pointer", 17: "FileTime", 18: "SystemTime", 19: "SID",
    20: "HexInt32", 21: "HexInt64", 22: "CountedString",
    23: "CountedAnsiString", 24: "Struct", 25: "CountedBinary",
}

TLGOUT_NAMES = {
    0: "", 1: "NoPrint", 2: "String", 3: "Boolean", 4: "Hex",
    5: "PID", 6: "TID", 7: "Port", 8: "IPv4", 9: "IPv6",
    10: "SocketAddress", 11: "XML", 12: "JSON", 13: "Win32Error",
    14: "NTStatus", 15: "HResult", 16: "FileTime", 17: "Signed",
    18: "Unsigned", 35: "UTF8", 36: "PKCS7", 37: "CodePointer",
    38: "DateTimeUTC",
}

_TLG_SIGNATURE = b"ETW0"
_TLG_MAGIC = 0xBB8A052B88040E86

try:
    _EXEC_FLAG = ida_segment.SEGPERM_EXEC
except AttributeError:
    _EXEC_FLAG = 1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class MemReader:
    """Cursor-based sequential reader over IDA memory."""
    def __init__(self, ea):
        self.ea = int(ea)

    @property
    def pos(self):
        return self.ea

    def u8(self):
        val = ida_bytes.get_byte(self.ea); self.ea += 1; return val

    def u16(self):
        val = ida_bytes.get_wide_word(self.ea); self.ea += 2; return val

    def u32(self):
        val = ida_bytes.get_wide_dword(self.ea); self.ea += 4; return val

    def u64(self):
        val = ida_bytes.get_qword(self.ea); self.ea += 8; return val

    def raw(self, size):
        val = ida_bytes.get_bytes(self.ea, size); self.ea += size; return val

    def cstr(self):
        out = bytearray()
        for _ in range(4096):
            byte = ida_bytes.get_byte(self.ea); self.ea += 1
            if byte == 0: break
            out.append(byte)
        else:
            return None
        if not out: return None
        try: return out.decode("utf-8")
        except: return None

    def skip(self, size):
        self.ea += size


def _fmt_guid(raw):
    if not raw or len(raw) != 16: return "Unknown"
    data1, data2, data3 = struct.unpack("<IHH", raw[:8])
    data4 = raw[8:]
    return (f"{{{data1:08X}-{data2:04X}-{data3:04X}"
            f"-{data4[:2].hex().upper()}-{data4[2:].hex().upper()}}}")


def _align8(ea):
    return ea + (8 - ea % 8) % 8


def check_prerequisites():
    if not idaapi.get_inf_structure().is_64bit():
        print("[!] TLGMapper requires an x64 binary.")
        return False
    return True


# ---------------------------------------------------------------------------
# Stage A-1: Find ETW0 headers
# ---------------------------------------------------------------------------

def find_etw0_headers():
    headers = []
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if not seg or (seg.perm & _EXEC_FLAG): continue
        ea = seg.start_ea
        while ea <= seg.end_ea - 16:
            if ida_bytes.get_bytes(ea, 4) == _TLG_SIGNATURE:
                size = ida_bytes.get_wide_word(ea + 4)
                magic = ida_bytes.get_qword(ea + 8)
                if size == 16 and magic == _TLG_MAGIC:
                    flags = ida_bytes.get_byte(ea + 7)
                    headers.append(ea)
                    print(f"  [+] ETW0 header at {hex(ea)} "
                          f"(flags={'64bit' if flags & 1 else '32bit'})")
                    ea += 16; continue
            ea += 4
    return headers


# ---------------------------------------------------------------------------
# Stage A-2: Parse event fields
# ---------------------------------------------------------------------------

def parse_event_fields(reader, end_ea):
    fields = []
    while reader.pos < end_ea:
        field_name = reader.cstr()
        if field_name is None: break
        in_value = reader.u8()
        in_type = in_value & 0x1F
        array_suffix = "[]" if in_value & 0x40 else ("[N]" if in_value & 0x20 else "")
        out_type_str = ""
        if in_value & 0x80:
            out_value = reader.u8(); out_type = out_value & 0x7F
            out_type_str = TLGOUT_NAMES.get(out_type, str(out_type))
            if out_value & 0x80:
                for _ in range(4):
                    if (reader.u8() & 0x80) == 0: break
        if (in_value & 0x60) == 0x20: reader.u16()
        if (in_value & 0x60) == 0x60:
            type_size = reader.u16(); reader.skip(type_size)
        type_name = TLGIN_NAMES.get(in_type, str(in_type))
        formatted = f"{type_name}{array_suffix}"
        if out_type_str: formatted += f"({out_type_str})"
        fields.append(f"{field_name}:{formatted}")
    return fields


# ---------------------------------------------------------------------------
# Stage A-2: Parse blobs
# ---------------------------------------------------------------------------

def _parse_provider_traits(reader, end_pos):
    group_guid = None
    if reader.pos < end_pos:
        chunk_size = reader.u16(); chunk_type = reader.u8()
        if chunk_type == 1 and chunk_size >= 19:
            group_guid = _fmt_guid(reader.raw(16))
        else:
            reader.skip(max(0, chunk_size - 3))
    reader.ea = end_pos
    return group_guid


def parse_blobs(header_ea):
    reader = MemReader(header_ea + 16)
    providers, events = [], []
    unknown_run = 0

    while True:
        blob_type = reader.u8()
        if blob_type == 1: break  # _TlgBlobEnd

        if blob_type == 0:  # padding
            unknown_run = 0; continue

        if blob_type == 4:  # _TlgBlobProvider3
            guid = reader.raw(16)
            registration_addr = reader.pos
            remaining = reader.u16()
            end_pos = reader.pos + remaining - 2
            name = reader.cstr()
            group_guid = _parse_provider_traits(reader, end_pos)
            providers.append({"name": name or "?", "guid": _fmt_guid(guid),
                              "group_guid": group_guid,
                              "rs_addr": registration_addr})
            unknown_run = 0; continue

        if blob_type == 2:  # _TlgBlobProvider (legacy, no GUID)
            registration_addr = reader.pos
            remaining = reader.u16()
            end_pos = reader.pos + remaining - 2
            name = reader.cstr()
            group_guid = _parse_provider_traits(reader, end_pos)
            providers.append({"name": name or "?", "guid": "Unknown(Type2)",
                              "group_guid": group_guid,
                              "rs_addr": registration_addr})
            unknown_run = 0; continue

        if blob_type in (3, 6):  # _TlgBlobEvent3 / _TlgBlobEvent4
            blob_start = reader.pos - 1
            channel = reader.u8(); level = reader.u8()
            opcode = reader.u8(); keyword = reader.u64()
            remaining = reader.u16()
            end_pos = reader.pos + remaining - 2
            for _ in range(4):
                if (reader.u8() & 0x80) == 0: break
            name = reader.cstr()
            fields = parse_event_fields(reader, end_pos)
            reader.ea = end_pos
            events.append({"name": name or "?", "channel": channel,
                           "level": level, "opcode": opcode,
                           "keyword": hex(keyword), "fields": fields,
                           "blob_start": blob_start, "blob_end": reader.pos})
            unknown_run = 0; continue

        if blob_type == 5:  # _TlgBlobEvent2 (legacy, no Channel)
            blob_start = reader.pos - 1
            level = reader.u8(); opcode = reader.u8(); reader.u16()  # task
            keyword = reader.u64()
            remaining = reader.u16()
            end_pos = reader.pos + remaining - 2
            for _ in range(4):
                if (reader.u8() & 0x80) == 0: break
            name = reader.cstr()
            fields = parse_event_fields(reader, end_pos)
            reader.ea = end_pos
            events.append({"name": name or "?", "channel": 0x0B,
                           "level": level, "opcode": opcode,
                           "keyword": hex(keyword), "fields": fields,
                           "blob_start": blob_start, "blob_end": reader.pos})
            unknown_run = 0; continue

        # Unknown byte — skip and keep trying
        unknown_run += 1
        if unknown_run > 128:
            print(f"  [!] Stopping parse after 128 unknown bytes at {hex(reader.pos)}")
            break

    return providers, events


# ---------------------------------------------------------------------------
# Stage A-3: Find _tlgProvider_t in .data
# ---------------------------------------------------------------------------

def find_provider_structs(parsed_providers):
    """Match known rs_addr values against qwords in .data."""
    registration_lookup = {p["rs_addr"]: p for p in parsed_providers}
    provider_map, known_bases = {}, set()

    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if not seg or (seg.perm & _EXEC_FLAG): continue
        ea = _align8(seg.start_ea)
        while ea < seg.end_ea - 8:
            val = ida_bytes.get_qword(ea)
            if val in registration_lookup:
                base = ea - 8
                prov_info = registration_lookup[val]
                known_bases.add(base)
                for offset in range(0, 64, 8):
                    provider_map[base + offset] = prov_info
                print(f"  [+] _tlgProvider_t '{prov_info['name']}' at {hex(base)}")
            ea += 8

    # Pass 2: indirect pointers
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if not seg or (seg.perm & _EXEC_FLAG): continue
        ea = _align8(seg.start_ea)
        while ea < seg.end_ea - 8:
            val = ida_bytes.get_qword(ea)
            if val in known_bases and ea not in provider_map:
                provider_map[ea] = provider_map[val]
            ea += 8

    return provider_map



# ---------------------------------------------------------------------------
# Stage B: Provider-Event Resolution
# ---------------------------------------------------------------------------

def _evt_for_addr(addr, events):
    for evt in events:
        if evt["blob_start"] <= addr < evt["blob_end"]:
            return evt
    return None


def link_events(provider_map, events, providers):
    """Stage B: walk functions, match DataRefsFrom, resolve providers.

    Resolution priority (based on empirical validation):
      1. SingleProvider       — Binary contains only one provider
      2. Direct-Preceding     — Provider ref appears before the event ref in the same function
      3. Direct-Nearest       — Closest provider ref by address in the same function
      4. CallGraph-dN         — DFS through callees (max depth: 3), searching backward first
      5. Unknown              — No provider could be resolved
    """

    # --- Pre-compute: single provider detection ---
    unique_mapped = set(p["name"] for p in provider_map.values()) if provider_map else set()
    unique_parsed = set(p["name"] for p in providers) if providers else set()
    single_provider = None
    if len(unique_mapped) == 1:
        single_provider = list(provider_map.values())[0]
    elif not unique_mapped and len(unique_parsed) == 1:
        single_provider = providers[0]

    # --- B-1: Walk functions ---
    print("[*] Walking functions for data references...")
    func_providers = {}   # func_ea → [(inst_ea, prov_info)]
    func_events = {}      # func_ea → [(inst_ea, evt_info)]
    func_calls = {}       # func_ea → [(inst_ea, callee_ea)]

    for func_ea in idautils.Functions():
        prov_refs, evt_refs, call_refs = [], [], []
        for head in idautils.FuncItems(func_ea):
            for data_ref in idautils.DataRefsFrom(head):
                data_ref = int(data_ref)
                if data_ref in provider_map:
                    prov_refs.append((head, provider_map[data_ref]))
                evt = _evt_for_addr(data_ref, events)
                if evt is not None:
                    evt_refs.append((head, evt))
            for code_ref in idautils.CodeRefsFrom(head, 0):
                callee = ida_funcs.get_func(code_ref)
                if callee and callee.start_ea != func_ea:
                    call_refs.append((head, callee.start_ea))
        func_providers[func_ea] = prov_refs
        func_events[func_ea] = evt_refs
        func_calls[func_ea] = call_refs

    # Deduplicated callee list for DFS
    func_callees = {}
    for func_ea, pairs in func_calls.items():
        seen, targets = set(), []
        for _, target in pairs:
            if target not in seen: seen.add(target); targets.append(target)
        func_callees[func_ea] = targets

    def _callgraph_dfs(func_ea, depth=0, max_depth=3, visited=None):
        if visited is None: visited = set()
        if func_ea in visited: return None, 0
        visited.add(func_ea)
        refs = func_providers.get(func_ea, [])
        if refs: return refs[0][1], depth
        if depth < max_depth:
            for target in func_callees.get(func_ea, []):
                result, found_depth = _callgraph_dfs(target, depth + 1, max_depth, visited)
                if result: return result, found_depth
        return None, 0

    # --- B-2: Resolve ---
    print("[*] Resolving providers per event...")
    results = []

    for func_ea, evt_refs in func_events.items():
        if not evt_refs: continue
        caller_name = ida_funcs.get_func_name(func_ea)
        prov_refs = func_providers.get(func_ea, [])
        call_pairs = func_calls.get(func_ea, [])

        for event_ea, event_info in evt_refs:
            prov_name, prov_guid, confidence = "Unknown", "Unknown", "Unresolved"

            # 1: SingleProvider — Single provider in binary
            if single_provider:
                prov_name = single_provider["name"]
                prov_guid = single_provider["guid"]
                confidence = "SingleProvider"

            # 2: Direct-Preceding — Provider ref appears before the event ref in the same function
            if confidence == "Unresolved" and prov_refs:
                preceding = [(addr, prov) for addr, prov in prov_refs if addr < event_ea]
                if preceding:
                    _, best_prov = max(preceding, key=lambda x: x[0])
                    prov_name = best_prov["name"]
                    prov_guid = best_prov["guid"]
                    confidence = "Direct-Preceding"

            # 3: Direct-Nearest — Closest provider ref by address in the same function
            if confidence == "Unresolved" and prov_refs:
                _, best_prov = min(prov_refs, key=lambda x: abs(x[0] - event_ea))
                prov_name = best_prov["name"]
                prov_guid = best_prov["guid"]
                confidence = "Direct-Nearest"

            # 4: CallGraph — DFS through callees (max depth: 3), searching backward first
            if confidence == "Unresolved" and call_pairs:
                backward_calls = sorted(
                    [(addr, target) for addr, target in call_pairs if addr <= event_ea],
                    key=lambda x: x[0], reverse=True)
                for _, target in backward_calls:
                    result, depth = _callgraph_dfs(target, depth=1)
                    if result:
                        prov_name = result["name"]
                        prov_guid = result["guid"]
                        confidence = f"CallGraph-d{depth}"
                        break
            if confidence == "Unresolved" and call_pairs:
                forward_calls = sorted(
                    [(addr, target) for addr, target in call_pairs if addr > event_ea],
                    key=lambda x: x[0])
                for _, target in forward_calls:
                    result, depth = _callgraph_dfs(target, depth=1)
                    if result:
                        prov_name = result["name"]
                        prov_guid = result["guid"]
                        confidence = f"CallGraph-d{depth}"
                        break

            fields_str = ", ".join(event_info.get("fields", [])) or "(none)"
            results.append({
                "Caller": caller_name, "InstructionEA": hex(event_ea),
                "Provider": prov_name, "GUID": prov_guid,
                "Event": event_info["name"], "Level": event_info["level"],
                "Keyword": event_info["keyword"], "Fields": fields_str,
                "Confidence": confidence,
            })

    return results


# ---------------------------------------------------------------------------
# IDA Choosers
# ---------------------------------------------------------------------------

class TLGLinkedChooser(ida_kernwin.Choose):
    """Linked events with caller, provider, and confidence."""
    COLS = [
        ["Provider",   30 | ida_kernwin.CHCOL_PLAIN],
        ["Event",      25 | ida_kernwin.CHCOL_PLAIN],
        ["Caller",     30 | ida_kernwin.CHCOL_PLAIN],
        ["EA",         16 | ida_kernwin.CHCOL_HEX],
        ["Level",       6 | ida_kernwin.CHCOL_DEC],
        ["Keyword",    18 | ida_kernwin.CHCOL_PLAIN],
        ["Fields",     40 | ida_kernwin.CHCOL_PLAIN],
        ["GUID",       40 | ida_kernwin.CHCOL_PLAIN],
        ["Confidence", 18 | ida_kernwin.CHCOL_PLAIN],
    ]
    def __init__(self, title, rows):
        super().__init__(title, [c for c, _ in self.COLS], width=140, height=30)
        self.rows = [[r["Provider"], r["Event"], r["Caller"],
                       r["InstructionEA"], str(r["Level"]), r["Keyword"],
                       r["Fields"], r["GUID"], r["Confidence"]] for r in rows]
    def OnGetSize(self): return len(self.rows)
    def OnGetLine(self, n): return self.rows[n]
    def OnSelectLine(self, n):
        try: idaapi.jumpto(int(self.rows[n][3], 16))
        except: pass


class TLGEventChooser(ida_kernwin.Choose):
    """All events from ETW0 metadata."""
    COLS = [
        ["Event",    30 | ida_kernwin.CHCOL_PLAIN],
        ["Level",     6 | ida_kernwin.CHCOL_DEC],
        ["Keyword",  18 | ida_kernwin.CHCOL_PLAIN],
        ["Opcode",    8 | ida_kernwin.CHCOL_DEC],
        ["Channel",   8 | ida_kernwin.CHCOL_DEC],
        ["Fields",   60 | ida_kernwin.CHCOL_PLAIN],
        ["BlobAddr", 18 | ida_kernwin.CHCOL_HEX],
    ]
    def __init__(self, title, evts):
        super().__init__(title, [c for c, _ in self.COLS], width=140, height=25)
        self.rows = [[e["name"], str(e["level"]), e["keyword"],
                       str(e["opcode"]), str(e["channel"]),
                       ", ".join(e.get("fields", [])) or "(none)",
                       hex(e["blob_start"])] for e in evts]
    def OnGetSize(self): return len(self.rows)
    def OnGetLine(self, n): return self.rows[n]
    def OnSelectLine(self, n):
        try: idaapi.jumpto(int(self.rows[n][6], 16))
        except: pass


# ---------------------------------------------------------------------------
# CSV output
# ---------------------------------------------------------------------------

def write_csv(results, path):
    fieldnames = ["Caller", "InstructionEA", "Provider", "GUID",
                  "Event", "Level", "Keyword", "Fields", "Confidence"]
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)
        print(f"[+] CSV saved: {path}")
    except Exception as e:
        print(f"[!] CSV error: {e}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    try:
        if not check_prerequisites(): return

        # Wait for IDA's auto-analysis to complete.
        # Essential when running against raw binaries (.exe/.dll/.sys)
        ida_auto.auto_wait()

        print("=" * 60)
        print("[*] TLGMapper.py — TraceLogging provider/event resolver")
        print("=" * 60)

        # A-1: ETW0
        headers = find_etw0_headers()
        if not headers:
            print("[-] No ETW0 header found. Binary has no TraceLogging metadata.")
            return

        # A-2: Parse blobs
        all_providers, all_events = [], []
        for header_ea in headers:
            provs, evts = parse_blobs(header_ea)
            all_providers.extend(provs); all_events.extend(evts)

        print(f"\n[*] Parsed: {len(all_providers)} provider(s), {len(all_events)} event(s)")
        for prov in all_providers:
            print(f"  Provider: {prov['name']}  GUID={prov['guid']}")
        for evt in all_events:
            print(f"  Event: {evt['name']}  Level={evt['level']}  "
                  f"Keyword={evt['keyword']}  Fields={len(evt.get('fields', []))}")

        if not all_events:
            print("[-] No events found in metadata.")
            return

        # A-3: _tlgProvider_t
        print("\n[*] Locating _tlgProvider_t runtime structures...")
        provider_map = find_provider_structs(all_providers)
        if not provider_map:
            print("[!] No _tlgProvider_t found in .data. "
                  "Only SingleProvider will be available.")

        # B: Link
        results = link_events(provider_map, all_events, all_providers)

        if results:
            results.sort(key=lambda x: (x["Provider"], x["Event"], x["Caller"]))
        print(f"\n[*] Total linked: {len(results)}")

        # Summary
        provider_events = {}
        for row in results:
            provider_events.setdefault(row["Provider"], set()).add(row["Event"])
        for prov, evts in sorted(provider_events.items()):
            print(f"  {prov}: {len(evts)} unique event(s)")
        confidence_counts = {}
        for row in results:
            confidence_counts[row["Confidence"]] = confidence_counts.get(row["Confidence"], 0) + 1
        for conf, count in sorted(confidence_counts.items()):
            print(f"  [{conf}]: {count}")

        # Choosers
        binary_name = ida_nalt.get_root_filename() or "unknown"
        if all_events:
            TLGEventChooser(f"TLG events — {binary_name}", all_events).Show()
        if results:
            TLGLinkedChooser(f"TLG linked — {binary_name}", results).Show()

        # Batch CSV
        if len(idc.ARGV) > 1:
            output_dir = idc.ARGV[1]
            if not os.path.exists(output_dir):
                try: os.makedirs(output_dir)
                except: output_dir = "."
            write_csv(results, os.path.join(output_dir, f"{binary_name}_tlg.csv"))

    except Exception as e:
        print(f"[!] FATAL: {e}")
        traceback.print_exc()
    finally:
        if len(idc.ARGV) > 1:
            idaapi.qexit(0)


if __name__ == "__main__":
    main()