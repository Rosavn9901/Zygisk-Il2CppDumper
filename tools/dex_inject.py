#!/usr/bin/env python3
"""
dex_inject.py — Pure-Python DEX patcher (no Java / apktool required)

Injects System.loadLibrary("il2cpp-dump") into the Application subclass
(attachBaseContext or onCreate) inside the DEX files of smali.zip.

Usage:
    python3 tools/dex_inject.py <smali.zip> [output.zip]
"""

import hashlib
import io
import os
import struct
import sys
import zipfile
import zlib

# ─────────────────────────────────────────────────────────────────────────────
# LEB128
# ─────────────────────────────────────────────────────────────────────────────

def _uleb128_decode(data, pos):
    v, s = 0, 0
    while True:
        b = data[pos]; pos += 1
        v |= (b & 0x7F) << s; s += 7
        if not (b & 0x80): return v, pos

def _uleb128_encode(v):
    out = []
    while True:
        b = v & 0x7F; v >>= 7
        if v: b |= 0x80
        out.append(b)
        if not v: break
    return bytes(out)

def _sleb128_decode(data, pos):
    v, s = 0, 0
    while True:
        b = data[pos]; pos += 1
        v |= (b & 0x7F) << s; s += 7
        if not (b & 0x80):
            if s < 64 and (b & 0x40): v |= -(1 << s)
            break
    return v, pos

# ─────────────────────────────────────────────────────────────────────────────
# MUTF-8
# ─────────────────────────────────────────────────────────────────────────────

def _mutf8_encode(s):
    out = bytearray()
    for ch in s:
        cp = ord(ch)
        if cp == 0:       out += b'\xc0\x80'
        elif cp < 0x80:   out.append(cp)
        elif cp < 0x800:  out += bytes([0xC0|(cp>>6), 0x80|(cp&0x3F)])
        else:             out += bytes([0xE0|(cp>>12), 0x80|((cp>>6)&0x3F), 0x80|(cp&0x3F)])
    return bytes(out)

def _mutf8_decode_str(data, off):
    _, pos = _uleb128_decode(data, off)
    start  = pos
    while data[pos] != 0: pos += 1
    try:    return bytes(data[start:pos]).decode('utf-8', errors='replace')
    except: return bytes(data[start:pos]).decode('latin-1')

# ─────────────────────────────────────────────────────────────────────────────
# code_item layout (DEX spec):
#   0  H  registers_size
#   2  H  ins_size
#   4  H  outs_size
#   6  H  tries_size
#   8  I  debug_info_off
#   12 I  insns_size  (in 16-bit code units)
#   16 …  insns
# ─────────────────────────────────────────────────────────────────────────────

CI_FMT       = '<HHHH II'
CI_HDR_BYTES = 16

def _read_code_item(data, off):
    regs, ins_sz, outs, tries, dbg_off, insns_sz = struct.unpack_from(CI_FMT, data, off)
    insns = bytes(data[off+CI_HDR_BYTES : off+CI_HDR_BYTES + insns_sz*2])
    return regs, ins_sz, outs, tries, dbg_off, insns_sz, insns


# ─────────────────────────────────────────────────────────────────────────────
# DEX
# ─────────────────────────────────────────────────────────────────────────────

class Dex:
    def __init__(self, raw: bytes):
        self.raw = bytearray(raw)
        self._parse()

    def _parse(self):
        d = self.raw
        assert d[0:4] == b'dex\n', "Not a DEX file"
        self.version = bytes(d[4:8])
        (self.file_size,
         self.hdr_size, self.endian,
         self.link_size, self.link_off,
         self.map_off,
         self.str_ids_size, self.str_ids_off,
         self.typ_ids_size, self.typ_ids_off,
         self.pro_ids_size, self.pro_ids_off,
         self.fld_ids_size, self.fld_ids_off,
         self.mth_ids_size, self.mth_ids_off,
         self.cls_dfs_size, self.cls_dfs_off,
         self.data_size,    self.data_off,
        ) = struct.unpack_from('<20I', d, 32)

        self._parse_strings()
        self._parse_types()
        self._parse_protos()
        self._parse_fields()
        self._parse_methods()
        self._parse_classdefs()

    def _parse_strings(self):
        d = self.raw
        self.str_ids = []
        self.strings  = []
        off = self.str_ids_off
        for i in range(self.str_ids_size):
            (sid,) = struct.unpack_from('<I', d, off + i*4)
            self.str_ids.append(sid)
            self.strings.append(_mutf8_decode_str(d, sid))

    def _parse_types(self):
        d = self.raw
        off = self.typ_ids_off
        self.type_ids = [struct.unpack_from('<I', d, off+i*4)[0]
                         for i in range(self.typ_ids_size)]

    def _parse_protos(self):
        d = self.raw
        off = self.pro_ids_off
        self.protos = []
        for i in range(self.pro_ids_size):
            sh, rt, po = struct.unpack_from('<III', d, off+i*12)
            params = []
            if po:
                (psz,) = struct.unpack_from('<I', d, po)
                for j in range(psz):
                    (ti,) = struct.unpack_from('<H', d, po+4+j*2)
                    params.append(ti)
            self.protos.append({'shorty': sh, 'ret': rt, 'params': params})

    def _parse_fields(self):
        d = self.raw
        off = self.fld_ids_off
        self.field_ids = [struct.unpack_from('<HHI', d, off+i*8)
                          for i in range(self.fld_ids_size)]

    def _parse_methods(self):
        d = self.raw
        off = self.mth_ids_off
        self.method_ids = [struct.unpack_from('<HHI', d, off+i*8)
                           for i in range(self.mth_ids_size)]

    def _parse_classdefs(self):
        d = self.raw
        off = self.cls_dfs_off
        self.class_defs = [list(struct.unpack_from('<8I', d, off+i*32))
                           for i in range(self.cls_dfs_size)]

    # ── lookup ────────────────────────────────────────────────────────────────

    def str_idx(self, s):
        lo, hi = 0, len(self.strings)
        while lo < hi:
            mid = (lo+hi)//2
            if   self.strings[mid] < s: lo = mid+1
            elif self.strings[mid] > s: hi = mid
            else:                       return mid, True
        return lo, False

    def type_idx_for(self, descriptor):
        si, ok = self.str_idx(descriptor)
        if not ok: return None
        for i, ti in enumerate(self.type_ids):
            if ti == si: return i
        return None

    def method_idx_for(self, class_desc, name, shorty_str):
        ci  = self.type_idx_for(class_desc)
        ni, ok  = self.str_idx(name)
        if ci is None or not ok: return None
        shi, ok2 = self.str_idx(shorty_str)
        if not ok2: return None
        valid = {i for i, p in enumerate(self.protos) if p['shorty'] == shi}
        for i, (mc, mp, mn) in enumerate(self.method_ids):
            if mc == ci and mn == ni and mp in valid: return i
        return None

    def get_method_name(self, midx):
        if midx < len(self.method_ids):
            return self.strings[self.method_ids[midx][2]]
        return ''

    # ── ensure (add if absent) ────────────────────────────────────────────────

    def ensure_string(self, s):
        idx, found = self.str_idx(s)
        if found: return idx
        self.strings.insert(idx, s)
        self.str_ids.insert(idx, 0)
        self.type_ids  = [ti+1 if ti>=idx else ti for ti in self.type_ids]
        for p in self.protos:
            if p['shorty'] >= idx: p['shorty'] += 1
            if p['ret']    >= idx: p['ret']    += 1
        self.field_ids  = [(c, t, n+1 if n>=idx else n) for c,t,n in self.field_ids]
        self.method_ids = [(c, p, n+1 if n>=idx else n) for c,p,n in self.method_ids]
        for cd in self.class_defs:
            if cd[4] != 0xFFFFFFFF and cd[4] >= idx: cd[4] += 1
        return idx

    def ensure_type(self, descriptor):
        si = self.ensure_string(descriptor)
        for i, ti in enumerate(self.type_ids):
            if ti == si: return i
        desc_str = self.strings[si]
        insert_at = len(self.type_ids)
        for i, ti in enumerate(self.type_ids):
            if self.strings[ti] > desc_str:
                insert_at = i; break
        self.type_ids.insert(insert_at, si)
        for p in self.protos:
            if p['ret'] >= insert_at: p['ret'] += 1
            p['params'] = [x+1 if x>=insert_at else x for x in p['params']]
        self.field_ids  = [(c+1 if c>=insert_at else c,
                            t+1 if t>=insert_at else t, n)
                           for c,t,n in self.field_ids]
        self.method_ids = [(c+1 if c>=insert_at else c, p, n)
                           for c,p,n in self.method_ids]
        for cd in self.class_defs:
            if cd[0] >= insert_at:                          cd[0] += 1
            if cd[2] != 0xFFFFFFFF and cd[2] >= insert_at: cd[2] += 1
        return insert_at

    def ensure_proto(self, shorty_str, ret_desc, param_descs):
        shi = self.ensure_string(shorty_str)
        ri  = self.ensure_type(ret_desc)
        pis = [self.ensure_type(d) for d in param_descs]
        for i, p in enumerate(self.protos):
            if p['shorty'] == shi and p['ret'] == ri and p['params'] == pis:
                return i
        self.protos.append({'shorty': shi, 'ret': ri, 'params': pis})
        return len(self.protos)-1

    def ensure_method(self, class_desc, name, shorty_str, ret_desc, param_descs):
        ci  = self.ensure_type(class_desc)
        ni  = self.ensure_string(name)
        pri = self.ensure_proto(shorty_str, ret_desc, param_descs)
        for i, (mc, mp, mn) in enumerate(self.method_ids):
            if mc == ci and mp == pri and mn == ni: return i
        key = (ci, pri, ni)
        insert_at = len(self.method_ids)
        for i, (mc, mp, mn) in enumerate(self.method_ids):
            if (mc, mp, mn) > key:
                insert_at = i; break
        self.method_ids.insert(insert_at, (ci, pri, ni))
        return insert_at

    # ── class data reader ────────────────────────────────────────────────────

    def read_class_data(self, off):
        """Return list of (method_idx, access_flags, code_off) for all methods."""
        d = self.raw
        sf,  off = _uleb128_decode(d, off)
        inf, off = _uleb128_decode(d, off)
        dm,  off = _uleb128_decode(d, off)
        vm,  off = _uleb128_decode(d, off)
        for _ in range(sf+inf):
            _, off = _uleb128_decode(d, off)
            _, off = _uleb128_decode(d, off)
        methods = []; cur = 0
        for _ in range(dm+vm):
            diff, off  = _uleb128_decode(d, off)
            flags, off = _uleb128_decode(d, off)
            coff,  off = _uleb128_decode(d, off)
            cur += diff
            methods.append((cur, flags, coff))
        return methods

    # ─────────────────────────────────────────────────────────────────────────
    # Collect all code_offs referenced by all class_data in original
    # ─────────────────────────────────────────────────────────────────────────

    def _collect_all_code_offs(self):
        """Return set of all code_off values referenced by class_data in original."""
        seen = set()
        d = self.raw
        for cd in self.class_defs:
            off = cd[6]
            if off == 0: continue
            try:
                sf,  pos = _uleb128_decode(d, off)
                inf, pos = _uleb128_decode(d, pos)
                dm,  pos = _uleb128_decode(d, pos)
                vm,  pos = _uleb128_decode(d, pos)
                for _ in range(sf+inf):
                    _, pos = _uleb128_decode(d, pos)
                    _, pos = _uleb128_decode(d, pos)
                for _ in range(dm+vm):
                    _,    pos = _uleb128_decode(d, pos)
                    _,    pos = _uleb128_decode(d, pos)
                    coff, pos = _uleb128_decode(d, pos)
                    if coff: seen.add(coff)
            except Exception:
                pass
        return seen

    # ─────────────────────────────────────────────────────────────────────────
    # Serialise — correct two-pass approach:
    #   Pass 1: write all code items → build orig_to_new_code map
    #   Pass 2: write all class_data items (referencing the map)
    # ─────────────────────────────────────────────────────────────────────────

    def to_bytes(self, code_patches: dict) -> bytes:
        """
        code_patches = { orig_code_off: prepend_bytes }
        """
        out  = io.BytesIO()
        orig = bytes(self.raw)

        def align4():
            r = out.tell() % 4
            if r: out.write(b'\x00' * (4-r))

        # ── 1. Header placeholder ─────────────────────────────────────────
        out.write(b'\x00' * 112)

        # ── 2. String IDs (back-filled after data) ────────────────────────
        str_ids_off = out.tell()
        str_id_table = [0] * len(self.strings)
        out.write(b'\x00' * (len(self.strings) * 4))

        # ── 3. Type IDs ───────────────────────────────────────────────────
        align4(); typ_ids_off = out.tell()
        for ti in self.type_ids:
            out.write(struct.pack('<I', ti))

        # ── 4. Proto IDs (params_off filled after type-lists) ─────────────
        align4(); pro_ids_off = out.tell()
        proto_param_slots = []   # (slot_pos, params_list)
        for p in self.protos:
            out.write(struct.pack('<II', p['shorty'], p['ret']))
            proto_param_slots.append((out.tell(), p['params']))
            out.write(struct.pack('<I', 0))

        # ── 5. Field IDs ──────────────────────────────────────────────────
        align4(); fld_ids_off = out.tell()
        for c, t, n in self.field_ids:
            out.write(struct.pack('<HHI', c, t, n))

        # ── 6. Method IDs ─────────────────────────────────────────────────
        align4(); mth_ids_off = out.tell()
        for c, p, n in self.method_ids:
            out.write(struct.pack('<HHI', c, p, n))

        # ── 7. Class defs (placeholders for offsets in data) ──────────────
        align4(); cls_dfs_off = out.tell()
        cd_data_slots  = []   # position of class_data_off field per class
        cd_sv_slots    = []   # position of static_values_off field per class
        for cd in self.class_defs:
            out.write(struct.pack('<IIII', cd[0], cd[1], cd[2], cd[3]))
            out.write(struct.pack('<II',   cd[4], cd[5]))
            cd_data_slots.append(out.tell()); out.write(struct.pack('<I', 0))
            cd_sv_slots.append(out.tell());   out.write(struct.pack('<I', 0))

        # ── DATA SECTION ──────────────────────────────────────────────────
        align4(); data_off = out.tell()

        # ── 8. String data ────────────────────────────────────────────────
        for i, s in enumerate(self.strings):
            str_id_table[i] = out.tell()
            enc = _mutf8_encode(s)
            out.write(_uleb128_encode(len(s)))
            out.write(enc)
            out.write(b'\x00')

        # ── 9. Type lists for proto params ────────────────────────────────
        param_map = {}
        for slot_pos, params in proto_param_slots:
            if not params: continue
            key = tuple(params)
            if key not in param_map:
                align4(); param_map[key] = out.tell()
                out.write(struct.pack('<I', len(params)))
                for ti in params: out.write(struct.pack('<H', ti))
            cur = out.tell()
            out.seek(slot_pos); out.write(struct.pack('<I', param_map[key]))
            out.seek(cur)

        # ── 10. Interface type_lists ───────────────────────────────────────
        iface_map = {}
        for i, cd in enumerate(self.class_defs):
            iface_off = cd[3]
            if not iface_off: continue
            if iface_off not in iface_map:
                (sz,) = struct.unpack_from('<I', orig, iface_off)
                blob = orig[iface_off : iface_off + 4 + sz*2]
                align4(); iface_map[iface_off] = out.tell()
                out.write(blob)
            cls_def_base = cls_dfs_off + i*32
            cur = out.tell()
            out.seek(cls_def_base + 12); out.write(struct.pack('<I', iface_map[iface_off]))
            out.seek(cur)

        # ── 11. CODE ITEMS — PASS 1: write everything, build offset map ───
        # KEY FIX: write ALL code items BEFORE writing any class_data.
        # This avoids the interleaving bug where copy_code_item wrote into
        # the middle of class_data bytes.
        orig_to_new_code = {}   # orig_code_off → new_code_off

        def write_code_item(orig_code_off):
            """Write one code item to out; return its new offset."""
            if orig_code_off == 0:
                return 0
            if orig_code_off in orig_to_new_code:
                return orig_to_new_code[orig_code_off]

            regs, ins_sz, outs, tries, dbg_off, insns_sz, insns = \
                _read_code_item(orig, orig_code_off)
            prepend = code_patches.get(orig_code_off, b'')

            align4(); new_off = out.tell()
            orig_to_new_code[orig_code_off] = new_off

            new_regs     = max(regs, 1) if prepend else regs
            new_outs     = max(outs, 1) if prepend else outs
            new_insns_sz = insns_sz + len(prepend) // 2

            # Zero debug_info_off — keeps DEX valid without needing to copy
            # debug_info blobs (which are large and complex to relocate).
            out.write(struct.pack('<HHHH', new_regs, ins_sz, new_outs, tries))
            out.write(struct.pack('<II', 0, new_insns_sz))   # dbg_off=0
            out.write(prepend)
            out.write(insns)

            if tries:
                orig_insns_end  = orig_code_off + CI_HDR_BYTES + insns_sz * 2
                pad_src         = (4 - (orig_insns_end % 4)) % 4
                tries_src       = orig_insns_end + pad_src

                new_insns_end   = out.tell()
                pad_dst         = (4 - (new_insns_end % 4)) % 4
                out.write(b'\x00' * pad_dst)

                # try_item list: tries × 8 bytes
                out.write(orig[tries_src : tries_src + tries * 8])

                # handler list (variable-length) — copy verbatim
                hpos = tries_src + tries * 8
                hlist_start = hpos
                hl_sz, hpos = _uleb128_decode(orig, hpos)
                for _ in range(hl_sz):
                    cc, hpos = _sleb128_decode(orig, hpos)
                    for _ in range(abs(cc)):
                        _, hpos = _uleb128_decode(orig, hpos)
                        _, hpos = _uleb128_decode(orig, hpos)
                    if cc <= 0:
                        _, hpos = _uleb128_decode(orig, hpos)
                out.write(orig[hlist_start : hpos])

            return new_off

        # Collect and write all code items
        all_code_offs = self._collect_all_code_offs()
        # Write patched targets first so they're in the map before class_data pass
        for co in sorted(all_code_offs):
            write_code_item(co)

        # ── 12. CLASS DATA — PASS 2: use completed offset map ────────────
        def write_class_data(orig_cd_off, slot_pos):
            if not orig_cd_off: return
            d   = orig
            pos = orig_cd_off

            sf,  pos = _uleb128_decode(d, pos)
            inf, pos = _uleb128_decode(d, pos)
            dm,  pos = _uleb128_decode(d, pos)
            vm,  pos = _uleb128_decode(d, pos)

            align4(); new_cd_off = out.tell()
            cur = out.tell()
            out.seek(slot_pos); out.write(struct.pack('<I', new_cd_off))
            out.seek(cur)

            out.write(_uleb128_encode(sf))
            out.write(_uleb128_encode(inf))
            out.write(_uleb128_encode(dm))
            out.write(_uleb128_encode(vm))

            # fields (copy diff/access_flags pairs as-is)
            for _ in range(sf + inf):
                v1, pos = _uleb128_decode(d, pos)
                v2, pos = _uleb128_decode(d, pos)
                out.write(_uleb128_encode(v1))
                out.write(_uleb128_encode(v2))

            # methods — coff must be remapped; diff/flags copied as-is
            for _ in range(dm + vm):
                diff, pos  = _uleb128_decode(d, pos)
                flags, pos = _uleb128_decode(d, pos)
                coff,  pos = _uleb128_decode(d, pos)
                new_coff   = orig_to_new_code.get(coff, 0)
                out.write(_uleb128_encode(diff))
                out.write(_uleb128_encode(flags))
                out.write(_uleb128_encode(new_coff))

        for slot_pos, cd in zip(cd_data_slots, self.class_defs):
            write_class_data(cd[6], slot_pos)

        # ── 13. Static values ─────────────────────────────────────────────
        for slot_pos, cd in zip(cd_sv_slots, self.class_defs):
            if not cd[7]: continue
            raw_sv = self._copy_encoded_array(orig, cd[7])
            align4(); new_sv = out.tell()
            out.write(raw_sv)
            cur = out.tell()
            out.seek(slot_pos); out.write(struct.pack('<I', new_sv))
            out.seek(cur)

        # ── 14. Annotation directories (copy raw) ─────────────────────────
        ann_map = {}
        for i, cd in enumerate(self.class_defs):
            ann_off = cd[5]
            if not ann_off: continue
            if ann_off not in ann_map:
                ca, fs, ms, ps = struct.unpack_from('<IIII', orig, ann_off)
                blob_len = 16 + (fs + ms + ps) * 8
                blob = orig[ann_off : ann_off + blob_len]
                align4(); ann_map[ann_off] = out.tell()
                out.write(blob)
            cls_def_base = cls_dfs_off + i * 32
            cur = out.tell()
            out.seek(cls_def_base + 20); out.write(struct.pack('<I', ann_map[ann_off]))
            out.seek(cur)

        # ── 15. Map list ──────────────────────────────────────────────────
        align4(); map_off = out.tell()
        sections = [(tc, cnt, off_) for tc, cnt, off_ in [
            (0x0000, 1,                   0),
            (0x0001, len(self.strings),   str_ids_off),
            (0x0002, len(self.type_ids),  typ_ids_off),
            (0x0003, len(self.protos),    pro_ids_off),
            (0x0004, len(self.field_ids), fld_ids_off),
            (0x0005, len(self.method_ids),mth_ids_off),
            (0x0006, len(self.class_defs),cls_dfs_off),
            (0x1000, 1,                   map_off),
        ] if cnt > 0]
        out.write(struct.pack('<I', len(sections)))
        for tc, cnt, off_ in sections:
            out.write(struct.pack('<HHII', tc, 0, cnt, off_))

        # ── Finalise ──────────────────────────────────────────────────────
        result = bytearray(out.getvalue())

        # Back-fill string IDs
        for i, sid in enumerate(str_id_table):
            struct.pack_into('<I', result, str_ids_off + i*4, sid)

        file_size = len(result)
        data_size = file_size - data_off

        # Header
        result[0:4] = b'dex\n'
        result[4:8] = self.version
        struct.pack_into('<I',  result, 32,  file_size)
        struct.pack_into('<I',  result, 36,  112)
        struct.pack_into('<I',  result, 40,  0x12345678)
        struct.pack_into('<II', result, 44,  0, 0)
        struct.pack_into('<I',  result, 52,  map_off)
        struct.pack_into('<II', result, 56,  len(self.strings),    str_ids_off)
        struct.pack_into('<II', result, 64,  len(self.type_ids),   typ_ids_off)
        struct.pack_into('<II', result, 72,  len(self.protos),     pro_ids_off)
        struct.pack_into('<II', result, 80,  len(self.field_ids),  fld_ids_off)
        struct.pack_into('<II', result, 88,  len(self.method_ids), mth_ids_off)
        struct.pack_into('<II', result, 96,  len(self.class_defs), cls_dfs_off)
        struct.pack_into('<II', result, 104, data_size, data_off)

        sha1 = hashlib.sha1(bytes(result[32:])).digest()
        result[12:32] = sha1
        ck = zlib.adler32(bytes(result[12:])) & 0xFFFFFFFF
        struct.pack_into('<I', result, 8, ck)

        return bytes(result)

    # ── encoded_array / encoded_value helpers ─────────────────────────────────

    def _copy_encoded_array(self, data, off):
        pos = off
        sz, pos = _uleb128_decode(data, pos)
        for _ in range(sz):
            pos = self._skip_ev(data, pos)
        return bytes(data[off:pos])

    def _skip_ev(self, d, pos):
        b = d[pos]; pos += 1
        vtype = b & 0x1F; varg = (b >> 5) & 0x7
        if vtype in (0x00, 0x02, 0x03, 0x04): return pos
        if vtype in (0x06, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                     0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b):
            return pos + varg + 1
        if vtype == 0x1c:   # array
            sz, pos = _uleb128_decode(d, pos)
            for _ in range(sz): pos = self._skip_ev(d, pos)
        elif vtype == 0x1d: # annotation
            _, pos = _uleb128_decode(d, pos)
            sz, pos = _uleb128_decode(d, pos)
            for _ in range(sz):
                _, pos = _uleb128_decode(d, pos)
                pos = self._skip_ev(d, pos)
        # 0x1e = null, 0x1f = boolean → no extra bytes
        return pos


# ─────────────────────────────────────────────────────────────────────────────
# Injection opcodes
# ─────────────────────────────────────────────────────────────────────────────

def make_injection(string_idx: int, method_idx: int) -> bytes:
    """
    const-string v0, string_idx    → 4 bytes (2 code units)
    invoke-static {v0}, method_idx → 6 bytes (3 code units)
    Total: 10 bytes = 5 code units
    """
    const_str     = struct.pack('<BBH', 0x1a, 0x00, string_idx & 0xFFFF)
    invoke_static = bytes([0x71, 0x11]) + struct.pack('<H', method_idx & 0xFFFF) + b'\x00\x00'
    return const_str + invoke_static


# ─────────────────────────────────────────────────────────────────────────────
# Target class finder
# ─────────────────────────────────────────────────────────────────────────────

TARGET_METHOD_NAMES = ('attachBaseContext', 'onCreate')
LIB_STRING          = 'il2cpp-dump'
SYSTEM_CLASS        = 'Ljava/lang/System;'
LOADLIB_NAME        = 'loadLibrary'
LOADLIB_SHORTY      = 'VL'
LOADLIB_RET         = 'V'
LOADLIB_PARAMS      = ['Ljava/lang/String;']

APP_SUPERCLASSES = {
    'Landroid/app/Application;',
    'Landroidx/multidex/MultiDexApplication;',
}


def _find_target(dex: Dex):
    """
    Return (class_desc, code_off, method_name) — best injection site.
    Priority:
      1. App/MultiDex subclass with attachBaseContext
      2. App/MultiDex subclass with onCreate
      3. Any class with attachBaseContext (regardless of superclass)
      4. Activity subclass with onCreate
    """
    app_sup_tis = {dex.type_idx_for(s) for s in APP_SUPERCLASSES} - {None}
    act_ti      = dex.type_idx_for('Landroid/app/Activity;')

    candidates = {1: [], 2: [], 3: [], 4: []}

    for cd in dex.class_defs:
        if not cd[6]: continue
        try:
            class_desc = dex.strings[dex.type_ids[cd[0]]]
            sup_ti     = cd[2]
            is_app     = sup_ti in app_sup_tis
            is_act     = act_ti is not None and sup_ti == act_ti
            methods    = dex.read_class_data(cd[6])
        except Exception:
            continue

        for midx, flags, coff in methods:
            if not coff: continue
            name = dex.get_method_name(midx)
            if name not in TARGET_METHOD_NAMES: continue

            if is_app and name == 'attachBaseContext':
                candidates[1].append((class_desc, coff, name))
            elif is_app and name == 'onCreate':
                candidates[2].append((class_desc, coff, name))
            elif name == 'attachBaseContext':
                candidates[3].append((class_desc, coff, name))
            elif is_act and name == 'onCreate':
                candidates[4].append((class_desc, coff, name))

    for prio in (1, 2, 3, 4):
        if candidates[prio]:
            return candidates[prio][0]
    return None


def _already_injected(dex: Dex, code_off: int) -> bool:
    d = dex.raw
    insns_sz = struct.unpack_from('<I', d, code_off + 12)[0]
    if insns_sz > 0x100000: return False
    insns_off = code_off + CI_HDR_BYTES
    for i in range(insns_sz):
        boff = insns_off + i * 2
        if boff + 3 >= len(d): break
        if d[boff] == 0x1a:
            si = struct.unpack_from('<H', d, boff+2)[0]
            if si < len(dex.strings) and dex.strings[si] == LIB_STRING:
                return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Per-DEX injection
# ─────────────────────────────────────────────────────────────────────────────

def inject_dex(raw: bytes) -> bytes:
    try:
        dex = Dex(raw)
    except Exception as e:
        print(f"    [!] DEX parse error: {e}")
        return raw

    target = _find_target(dex)
    if target is None:
        return raw

    class_desc, code_off, method_name = target
    print(f"    [*] Target: {class_desc[:70]}::{method_name}()  code_off=0x{code_off:x}")

    if _already_injected(dex, code_off):
        print("    [*] Already injected, skipping")
        return raw

    # Sanity check code_off
    d = dex.raw
    insns_sz = struct.unpack_from('<I', d, code_off + 12)[0]
    if insns_sz > 0x100000 or code_off + CI_HDR_BYTES + insns_sz*2 > len(d):
        print(f"    [!] Suspicious code_off=0x{code_off:x} insns_sz={insns_sz} — skipping")
        return raw

    print("    [*] Ensuring required strings/methods...")
    lib_si  = dex.ensure_string(LIB_STRING)
    _       = dex.ensure_type(SYSTEM_CLASS)
    _       = dex.ensure_type('Ljava/lang/String;')
    mth_idx = dex.ensure_method(SYSTEM_CLASS, LOADLIB_NAME,
                                 LOADLIB_SHORTY, LOADLIB_RET, LOADLIB_PARAMS)
    lib_si, _ = dex.str_idx(LIB_STRING)   # re-resolve after any shifts

    print(f"    [+] string_idx={lib_si}  method_idx={mth_idx}")
    injection = make_injection(lib_si, mth_idx)

    print("    [*] Rebuilding DEX...")
    try:
        result = dex.to_bytes({code_off: injection})
        print(f"    [+] Done: {len(raw):,} → {len(result):,} bytes")
        return result
    except Exception as e:
        import traceback; traceback.print_exc()
        print(f"    [!] Rebuild failed: {e}")
        return raw


# ─────────────────────────────────────────────────────────────────────────────
# ZIP wrapper
# ─────────────────────────────────────────────────────────────────────────────

def patch_zip(in_zip: str, out_zip: str) -> bool:
    injected = False
    with zipfile.ZipFile(in_zip, 'r') as zin:
        names     = zin.namelist()
        dex_names = sorted(n for n in names if n.endswith('.dex'))
        rest      = [n for n in names if not n.endswith('.dex')]
        print(f"[*] DEX files: {dex_names}\n")
        with zipfile.ZipFile(out_zip, 'w', compression=zipfile.ZIP_STORED) as zout:
            for name in rest:
                zout.writestr(name, zin.read(name))
            for dname in dex_names:
                print(f"[*] Processing {dname}...")
                raw     = zin.read(dname)
                patched = inject_dex(raw)
                if patched != raw:
                    injected = True
                    print(f"    [✓] {dname} patched\n")
                else:
                    print(f"    [-] {dname} unchanged\n")
                zout.writestr(dname, patched)
    return injected


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    in_zip  = sys.argv[1]
    out_zip = sys.argv[2] if len(sys.argv) > 2 else \
              os.path.splitext(in_zip)[0] + '_patched.zip'
    print(f"[*] Input : {in_zip}")
    print(f"[*] Output: {out_zip}\n")
    ok = patch_zip(in_zip, out_zip)
    if ok:
        print(f"[✓] Patched zip saved to: {out_zip}")
        print("    Next steps:")
        print("    1. Extract DEX files → replace originals in APK")
        print("    2. Add libil2cpp-dump.so to lib/<abi>/")
        print("    3. Re-sign with apksigner / jarsigner")
    else:
        print("[!] No injection performed — target class not found in any DEX.")


if __name__ == '__main__':
    main()
