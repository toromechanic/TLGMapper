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
  1. Direct-Preceding    — same function, nearest preceding prov ref
  2. Direct-Nearest      — same function, closest prov ref by address
  3. CallGraph-dN        — DFS through callees, event-proximity-aware
  4. GlobalFallback      — binary has only one provider
  5. Unknown

Results are displayed in IDA chooser windows. Batch mode writes CSV.

Usage (GUI):  File > Script file > TLGMapper.py
Usage (batch): ida64.exe -A -o"C:\output\<binary>.i64" -S"TLGMapper.py C:\output" -LC:\output\log.txt <binary>
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
        v = ida_bytes.get_byte(self.ea); self.ea += 1; return v

    def u16(self):
        v = ida_bytes.get_wide_word(self.ea); self.ea += 2; return v

    def u32(self):
        v = ida_bytes.get_wide_dword(self.ea); self.ea += 4; return v

    def u64(self):
        v = ida_bytes.get_qword(self.ea); self.ea += 8; return v

    def raw(self, n):
        v = ida_bytes.get_bytes(self.ea, n); self.ea += n; return v

    def cstr(self):
        out = bytearray()
        for _ in range(4096):
            b = ida_bytes.get_byte(self.ea); self.ea += 1
            if b == 0: break
            out.append(b)
        else:
            return None
        if not out: return None
        try: return out.decode("utf-8")
        except: return None

    def skip(self, n):
        self.ea += n


def _fmt_guid(raw):
    if not raw or len(raw) != 16: return "Unknown"
    d1, d2, d3 = struct.unpack("<IHH", raw[:8])
    d4 = raw[8:]
    return (f"{{{d1:08X}-{d2:04X}-{d3:04X}"
            f"-{d4[:2].hex().upper()}-{d4[2:].hex().upper()}}}")


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
                sz = ida_bytes.get_wide_word(ea + 4)
                mg = ida_bytes.get_qword(ea + 8)
                if sz == 16 and mg == _TLG_MAGIC:
                    fl = ida_bytes.get_byte(ea + 7)
                    headers.append(ea)
                    print(f"  [+] ETW0 header at {hex(ea)} "
                          f"(flags={'64bit' if fl & 1 else '32bit'})")
                    ea += 16; continue
            ea += 4
    return headers


# ---------------------------------------------------------------------------
# Stage A-2: Parse event fields
# ---------------------------------------------------------------------------

def parse_event_fields(r, end_ea):
    fields = []
    while r.pos < end_ea:
        fn = r.cstr()
        if fn is None: break
        inv = r.u8()
        it = inv & 0x1F
        arr = "[]" if inv & 0x40 else ("[N]" if inv & 0x20 else "")
        ots = ""
        if inv & 0x80:
            ov = r.u8(); ot = ov & 0x7F
            ots = TLGOUT_NAMES.get(ot, str(ot))
            if ov & 0x80:
                for _ in range(4):
                    if (r.u8() & 0x80) == 0: break
        if (inv & 0x60) == 0x20: r.u16()
        if (inv & 0x60) == 0x60:
            ts = r.u16(); r.skip(ts)
        nm = TLGIN_NAMES.get(it, str(it))
        t = f"{nm}{arr}"
        if ots: t += f"({ots})"
        fields.append(f"{fn}:{t}")
    return fields


# ---------------------------------------------------------------------------
# Stage A-2: Parse blobs
# ---------------------------------------------------------------------------

def _parse_provider_traits(r, end_pos):
    gg = None
    if r.pos < end_pos:
        cs = r.u16(); ct = r.u8()
        if ct == 1 and cs >= 19:
            gg = _fmt_guid(r.raw(16))
        else:
            r.skip(max(0, cs - 3))
    r.ea = end_pos
    return gg


def parse_blobs(header_ea):
    r = MemReader(header_ea + 16)
    providers, events = [], []
    unk_run = 0

    while True:
        bt = r.u8()
        if bt == 1: break  # _TlgBlobEnd

        if bt == 0:  # padding
            unk_run = 0; continue

        if bt == 4:  # _TlgBlobProvider3
            bs = r.pos - 1
            guid = r.raw(16)
            rs = r.pos
            rem = r.u16()
            ep = r.pos + rem - 2
            nm = r.cstr()
            gg = _parse_provider_traits(r, ep)
            providers.append({"name": nm or "?", "guid": _fmt_guid(guid),
                              "group_guid": gg, "rs_addr": rs,
                              "blob_start": bs, "blob_end": r.pos})
            unk_run = 0; continue

        if bt == 2:  # _TlgBlobProvider (legacy, no GUID)
            bs = r.pos - 1
            rs = r.pos
            rem = r.u16()
            ep = r.pos + rem - 2
            nm = r.cstr()
            gg = _parse_provider_traits(r, ep)
            providers.append({"name": nm or "?", "guid": "Unknown(Type2)",
                              "group_guid": gg, "rs_addr": rs,
                              "blob_start": bs, "blob_end": r.pos})
            unk_run = 0; continue

        if bt in (3, 6):  # _TlgBlobEvent3 / _TlgBlobEvent4
            bs = r.pos - 1
            ch = r.u8(); lv = r.u8(); op = r.u8(); kw = r.u64()
            rem = r.u16(); ep = r.pos + rem - 2
            for _ in range(4):
                if (r.u8() & 0x80) == 0: break
            nm = r.cstr()
            fl = parse_event_fields(r, ep)
            r.ea = ep
            events.append({"name": nm or "?", "channel": ch, "level": lv,
                           "opcode": op, "keyword": hex(kw), "fields": fl,
                           "blob_start": bs, "blob_end": r.pos})
            unk_run = 0; continue

        if bt == 5:  # _TlgBlobEvent2 (legacy, no Channel)
            bs = r.pos - 1
            lv = r.u8(); op = r.u8(); r.u16()  # task
            kw = r.u64(); rem = r.u16(); ep = r.pos + rem - 2
            for _ in range(4):
                if (r.u8() & 0x80) == 0: break
            nm = r.cstr()
            fl = parse_event_fields(r, ep)
            r.ea = ep
            events.append({"name": nm or "?", "channel": 0x0B, "level": lv,
                           "opcode": op, "keyword": hex(kw), "fields": fl,
                           "blob_start": bs, "blob_end": r.pos})
            unk_run = 0; continue

        # Unknown byte — skip and keep trying
        unk_run += 1
        if unk_run > 128:
            print(f"  [!] Stopping parse after 128 unknown bytes at {hex(r.pos)}")
            break

    return providers, events


# ---------------------------------------------------------------------------
# Stage A-3: Find _tlgProvider_t in .data
# ---------------------------------------------------------------------------

def find_provider_structs(parsed_providers):
    """Match known rs_addr values against qwords in .data."""
    rs_lookup = {p["rs_addr"]: p for p in parsed_providers}
    pmap, bases = {}, set()

    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if not seg or (seg.perm & _EXEC_FLAG): continue
        ea = _align8(seg.start_ea)
        while ea < seg.end_ea - 8:
            v = ida_bytes.get_qword(ea)
            if v in rs_lookup:
                base = ea - 8
                pi = rs_lookup[v]; bases.add(base)
                for off in range(0, 64, 8):
                    pmap[base + off] = pi
                print(f"  [+] _tlgProvider_t '{pi['name']}' at {hex(base)}")
            ea += 8

    # Pass 2: indirect pointers
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if not seg or (seg.perm & _EXEC_FLAG): continue
        ea = _align8(seg.start_ea)
        while ea < seg.end_ea - 8:
            v = ida_bytes.get_qword(ea)
            if v in bases and ea not in pmap:
                pmap[ea] = pmap[v]
            ea += 8

    return pmap



# ---------------------------------------------------------------------------
# Stage B: Link events to functions and resolve providers
# ---------------------------------------------------------------------------

def _evt_for_addr(addr, events):
    for e in events:
        if e["blob_start"] <= addr < e["blob_end"]:
            return e
    return None


def link_events(pmap, events, providers):
    """Stage B: walk functions, match DataRefsFrom, resolve providers."""

    # --- Pre-compute: single provider fallback ---
    uniq_map = set(p["name"] for p in pmap.values()) if pmap else set()
    uniq_parsed = set(p["name"] for p in providers) if providers else set()
    single = None
    if len(uniq_map) == 1:
        single = list(pmap.values())[0]
    elif not uniq_map and len(uniq_parsed) == 1:
        single = providers[0]

    # --- B-1: Walk functions ---
    print("[*] Walking functions for data references...")
    f_provs = {}   # func → [(inst_ea, prov_info)]
    f_evts = {}    # func → [(inst_ea, evt_info)]
    f_calls = {}   # func → [(inst_ea, callee_ea)]

    for fea in idautils.Functions():
        pr, ev, cl = [], [], []
        for h in idautils.FuncItems(fea):
            for d in idautils.DataRefsFrom(h):
                d = int(d)
                if d in pmap:
                    pr.append((h, pmap[d]))
                e = _evt_for_addr(d, events)
                if e is not None:
                    ev.append((h, e))
            for c in idautils.CodeRefsFrom(h, 0):
                cf = ida_funcs.get_func(c)
                if cf and cf.start_ea != fea:
                    cl.append((h, cf.start_ea))
        f_provs[fea] = pr
        f_evts[fea] = ev
        f_calls[fea] = cl

    # Deduplicated callee list for DFS
    f_callees = {}
    for fea, pairs in f_calls.items():
        seen, lst = set(), []
        for _, tgt in pairs:
            if tgt not in seen: seen.add(tgt); lst.append(tgt)
        f_callees[fea] = lst

    def _cg_dfs(fea, d=0, mx=3, vis=None):
        if vis is None: vis = set()
        if fea in vis: return None, 0
        vis.add(fea)
        refs = f_provs.get(fea, [])
        if refs: return refs[0][1], d
        if d < mx:
            for t in f_callees.get(fea, []):
                r, dd = _cg_dfs(t, d + 1, mx, vis)
                if r: return r, dd
        return None, 0

    # --- B-2: Resolve ---
    print("[*] Resolving providers per event...")
    results = []

    for fea, erefs in f_evts.items():
        if not erefs: continue
        caller = ida_funcs.get_func_name(fea)
        prefs = f_provs.get(fea, [])
        cpairs = f_calls.get(fea, [])

        for eea, einfo in erefs:
            pn, pg, conf = "Unknown", "Unknown", "Unresolved"

            # 1/2: Direct
            if prefs:
                pre = [(a, p) for a, p in prefs if a < eea]
                if pre:
                    _, bp = max(pre, key=lambda x: x[0])
                    pn, pg, conf = bp["name"], bp["guid"], "Direct-Preceding"
                else:
                    _, bp = min(prefs, key=lambda x: abs(x[0] - eea))
                    pn, pg, conf = bp["name"], bp["guid"], "Direct-Nearest"

            # 3: CallGraph (proximity-aware)
            if conf == "Unresolved" and cpairs:
                fol = sorted([(a, t) for a, t in cpairs if a > eea], key=lambda x: x[0])
                for _, t in fol:
                    r, d = _cg_dfs(t, d=1)
                    if r:
                        pn, pg, conf = r["name"], r["guid"], f"CallGraph-d{d}"
                        break
            if conf == "Unresolved" and cpairs:
                bef = sorted([(a, t) for a, t in cpairs if a <= eea], key=lambda x: x[0], reverse=True)
                for _, t in bef:
                    r, d = _cg_dfs(t, d=1)
                    if r:
                        pn, pg, conf = r["name"], r["guid"], f"CallGraph-d{d}"
                        break

            # 4: GlobalFallback
            if conf == "Unresolved" and single:
                pn, pg, conf = single["name"], single["guid"], "GlobalFallback"

            flds = ", ".join(einfo.get("fields", [])) or "(none)"
            results.append({
                "Caller": caller, "InstructionEA": hex(eea),
                "Provider": pn, "GUID": pg,
                "Event": einfo["name"], "Level": einfo["level"],
                "Keyword": einfo["keyword"], "Fields": flds,
                "Confidence": conf,
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
    fns = ["Caller", "InstructionEA", "Provider", "GUID",
           "Event", "Level", "Keyword", "Fields", "Confidence"]
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fns); w.writeheader(); w.writerows(results)
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
        # in batch mode — without this, Functions() and DataRefsFrom
        # may return incomplete results. Harmless when opening .i64.
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
        all_provs, all_evts = [], []
        for h in headers:
            p, e = parse_blobs(h)
            all_provs.extend(p); all_evts.extend(e)

        print(f"\n[*] Parsed: {len(all_provs)} provider(s), {len(all_evts)} event(s)")
        for p in all_provs:
            print(f"  Provider: {p['name']}  GUID={p['guid']}")
        for e in all_evts:
            print(f"  Event: {e['name']}  Level={e['level']}  "
                  f"Keyword={e['keyword']}  Fields={len(e.get('fields', []))}")

        if not all_evts:
            print("[-] No events found in metadata.")
            return

        # A-3: _tlgProvider_t
        print("\n[*] Locating _tlgProvider_t runtime structures...")
        pmap = find_provider_structs(all_provs)
        if not pmap:
            print("[!] No _tlgProvider_t found in .data. "
                  "Only GlobalFallback will be available.")

        # B: Link
        results = link_events(pmap, all_evts, all_provs)

        if results:
            results.sort(key=lambda x: (x["Provider"], x["Event"], x["Caller"]))
        print(f"\n[*] Total linked: {len(results)}")

        # Summary
        ps = {}
        for r in results:
            ps.setdefault(r["Provider"], set()).add(r["Event"])
        for p, es in sorted(ps.items()):
            print(f"  {p}: {len(es)} unique event(s)")
        cs = {}
        for r in results:
            cs[r["Confidence"]] = cs.get(r["Confidence"], 0) + 1
        for c, n in sorted(cs.items()):
            print(f"  [{c}]: {n}")

        # Choosers
        bn = ida_nalt.get_root_filename() or "unknown"
        if all_evts:
            TLGEventChooser(f"TLG events — {bn}", all_evts).Show()
        if results:
            TLGLinkedChooser(f"TLG linked — {bn}", results).Show()

        # Batch CSV
        if len(idc.ARGV) > 1:
            od = idc.ARGV[1]
            if not os.path.exists(od):
                try: os.makedirs(od)
                except: od = "."
            write_csv(results, os.path.join(od, f"{bn}_tlg.csv"))

    except Exception as e:
        print(f"[!] FATAL: {e}")
        traceback.print_exc()
    finally:
        if len(idc.ARGV) > 1:
            idaapi.qexit(0)


if __name__ == "__main__":
    main()