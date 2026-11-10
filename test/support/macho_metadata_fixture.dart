import 'dart:convert';
import 'dart:typed_data';

/// Independent on-disk ABI fixture: a class, metaclass, protocol, category,
/// relative Swift descriptors, a symbolic typeref containing embedded zeroes.
Uint8List metadataMachO(
    {bool wide = true,
    Endian endian = Endian.little,
    bool smallMethods = false,
    bool indirectMethods = false,
    bool chained = false,
    int chainFormat = 6}) {
  final b = Uint8List(8192);
  // Keep fixed payload offsets independent from load-command sizes.
  final data = ByteData.sublistView(b);
  final w = wide ? 8 : 4, base = wide ? 0x100000000 : 0x1000;
  void u32(int o, int v) => data.setUint32(o, v, endian);
  void u16(int o, int v) => data.setUint16(o, v, endian);
  void ptr(int o, int v) => wide ? data.setUint64(o, v, endian) : u32(o, v);
  void ref(int o, int target) => ptr(o, base + target);
  void rel(int o, int target) => data.setInt32(o, target - o, endian);
  void text(int o, String s) =>
      b.setRange(o, o + utf8.encode(s).length, utf8.encode(s));
  final sections = <(String, int, int)>[
    ('__objc_classlist', 2048, w),
    ('__objc_protolist', 2064, w),
    ('__objc_catlist', 2080, w),
    ('__swift5_types', 2100, 4),
    ('__swift5_protos', 2110, 4),
    ('__swift5_typeref', 2120, 7),
    ('__objc_classname', 4000, 11),
    ('__objc_methname', 4020, 13),
    ('__swift5_reflstr', 4140, 7),
  ];
  final header = wide ? 32 : 28, seg = wide ? 72 : 56, sec = wide ? 80 : 68;
  final segmentSize = seg + sec * sections.length;
  u32(0, wide ? 0xfeedfacf : 0xfeedface);
  u32(4, wide ? 0x0100000c : 12);
  u32(12, 2);
  u32(16, chained ? 3 : 2);
  u32(20, segmentSize + 24 + (chained ? 16 : 0));
  u32(header, wide ? 0x19 : 1);
  u32(header + 4, segmentSize);
  text(header + 8, '__DATA');
  ptr(header + 24, base);
  ptr(header + (wide ? 32 : 28), b.length);
  ptr(header + (wide ? 48 : 36), b.length);
  u32(header + (wide ? 60 : 44), 3);
  u32(header + (wide ? 64 : 48), sections.length);
  for (var i = 0; i < sections.length; i++) {
    final s = header + seg + sec * i;
    final (name, o, size) = sections[i];
    text(s, name);
    text(s + 16, '__DATA');
    ref(s + 32, o);
    ptr(s + (wide ? 40 : 36), size);
    u32(s + (wide ? 48 : 40), o);
  }
  final symtab = header + segmentSize;
  u32(symtab, 2);
  u32(symtab + 4, 24);
  u32(symtab + 8, 6000);
  u32(symtab + 16, 6000);
  u32(symtab + 20, 1);
  ref(2048, 2200);
  ref(2064, 2600);
  ref(2080, 2800);
  // class_t: isa, superclass, cache (two pointers), data (class_ro_t).
  ref(2200, 2300);
  ref(2200 + 4 * w, 2400);
  ref(2300 + 4 * w, 2512);
  final nameAt = wide ? 24 : 16,
      methodsAt = wide ? 32 : 20,
      protocolsAt = wide ? 40 : 24;
  ref(2400 + nameAt, 4000);
  ref(2512 + nameAt, 4000);
  ref(2400 + methodsAt, 3000);
  ref(2512 + methodsAt, 3100);
  ref(2400 + protocolsAt, 3200);
  ptr(3200, 1);
  ref(3200 + w, 2600);
  text(4000, 'GuardClass');
  text(4020, 'isJailbroken');
  text(4060, 'verifyAppSignature');
  text(4100, 'SecurityProtocol');
  text(4140, 'Device');
  text(4160, 'Extras');
  ref(2600 + w, 4100);
  ref(2600 + 3 * w, 3000);
  ref(2800, 4160);
  ref(2800 + w, 2200);
  ref(2800 + 2 * w, 3100);
  for (final (o, name) in [(3000, 4020), (3100, 4060)]) {
    if (smallMethods) {
      u32(o, (indirectMethods ? 0x80000000 : 0xc0000000) | 12);
      rel(o + 8, indirectMethods ? 3300 + (o - 3000) : name);
      if (indirectMethods) ref(3300 + (o - 3000), name);
    } else {
      u32(o, 3 * w);
      ref(o + 8, name);
    }
    u32(o + 4, 1);
  }
  // Swift module + class + protocol; stable descriptor version zero.
  u32(3500, 0);
  rel(3508, 4200);
  text(4200, 'Security');
  u32(3520, 16);
  rel(3524, 3500);
  rel(3528, 4220);
  text(4220, 'JailbreakDetector');
  u32(3560, 3);
  rel(3564, 3500);
  rel(3568, 4260);
  text(4260, 'IntegrityChecking');
  rel(2100, 3520);
  rel(2110, 3560);
  b[2120] = 1;
  rel(2121, 3520);
  b[2125] = 67;
  if (chained) {
    if (!wide || endian != Endian.little || smallMethods) {
      throw ArgumentError('Fixture format');
    }
    final cmd = symtab + 24;
    u32(cmd, 0x80000034);
    u32(cmd + 4, 16);
    u32(cmd + 8, 7000);
    u32(cmd + 12, 64);
    u32(7004, 28);
    u32(7028, 1);
    u32(7032, 8);
    u32(7036, 26);
    u16(7040, 4096);
    u16(7042, chainFormat);
    u16(7056, 2);
    final pointers = <int>[
      2048,
      2064,
      2080,
      2200,
      2200 + 4 * w,
      2300 + 4 * w,
      2400 + nameAt,
      2512 + nameAt,
      2400 + methodsAt,
      2512 + methodsAt,
      2400 + protocolsAt,
      3200 + w,
      2600 + w,
      2600 + 3 * w,
      2800,
      2800 + w,
      2800 + 2 * w,
      3008,
      3108,
    ]..sort();
    u16(7058, pointers.first);
    u16(7060, 0xffff);
    for (var i = 0; i < pointers.length; i++) {
      final o = pointers[i],
          next = i == pointers.length - 1 ? 0 : (pointers[i + 1] - o) ~/ 4;
      data.setUint64(
          o,
          (data.getUint64(o, endian) - (chainFormat == 6 ? base : 0)) |
              (next << 51),
          endian);
    }
  }
  return b;
}
