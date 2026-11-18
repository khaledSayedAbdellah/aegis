import 'dart:typed_data';

const _android = 'http://schemas.android.com/apk/res/android';
const _none = 0xFFFFFFFF;

/// An element for [axml]: its tag, string attributes as
/// (in the android namespace, name, value), and children.
class AxmlElement {
  const AxmlElement(this.tag,
      [this.attributes = const [], this.children = const []]);
  final String tag;
  final List<(bool, String, String)> attributes;
  final List<AxmlElement> children;
}

/// Android binary XML for [root], as aapt writes it (UTF-16 string pool,
/// string attributes only). A port of `axml()` in
/// tool/make_apk_fixtures.py, so tests can build manifests with values
/// that must not sit in a committed fixture.
Uint8List axml(AxmlElement root) {
  final strings = <String>['android', _android];
  void collect(AxmlElement e) {
    final AxmlElement(:tag, :attributes, :children) = e;
    for (final s in [
      tag,
      for (final a in attributes) ...[a.$2, a.$3]
    ]) {
      if (!strings.contains(s)) strings.add(s);
    }
    children.forEach(collect);
  }

  collect(root);
  int idx(String s) => strings.indexOf(s);

  Uint8List chunk(int type, int headerSize, List<int> header, List<int> body) {
    final size = 8 + header.length + body.length;
    final b = BytesBuilder()
      ..add(_u16(type))
      ..add(_u16(headerSize))
      ..add(_u32(size))
      ..add(header)
      ..add(body);
    return b.takeBytes();
  }

  final data = BytesBuilder();
  final offsets = <int>[];
  for (final s in strings) {
    offsets.add(data.length);
    final units = s.codeUnits;
    data
      ..add(_u16(units.length))
      ..add(Uint8List.view(Uint16List.fromList(units).buffer))
      ..add(const [0, 0]);
  }
  while (data.length % 4 != 0) {
    data.addByte(0);
  }
  final poolHeader = [
    ..._u32(strings.length), ..._u32(0), ..._u32(0), //
    ..._u32(28 + 4 * strings.length), ..._u32(0),
  ];
  final pool = chunk(0x0001, 28, poolHeader,
      [for (final o in offsets) ..._u32(o), ...data.takeBytes()]);
  final resmap = chunk(0x0180, 8, const [], const []);

  final body = BytesBuilder()
    ..add(chunk(0x0100, 16, [..._u32(1), ..._u32(_none)],
        [..._u32(idx('android')), ..._u32(idx(_android))]));
  void emit(AxmlElement e) {
    final AxmlElement(:tag, :attributes, :children) = e;
    final attrs = BytesBuilder();
    for (final (isAndroid, name, value) in attributes) {
      attrs
        ..add(_u32(isAndroid ? idx(_android) : _none))
        ..add(_u32(idx(name)))
        ..add(_u32(idx(value)))
        ..add(_u16(8))
        ..addByte(0)
        ..addByte(0x03)
        ..add(_u32(idx(value)));
    }
    final ext = [
      ..._u32(_none), ..._u32(idx(tag)), ..._u16(20), ..._u16(20), //
      ..._u16(attributes.length), ..._u16(0), ..._u16(0), ..._u16(0),
    ];
    body.add(chunk(0x0102, 16, [..._u32(1), ..._u32(_none)],
        [...ext, ...attrs.takeBytes()]));
    children.forEach(emit);
    body.add(chunk(0x0103, 16, [..._u32(1), ..._u32(_none)],
        [..._u32(_none), ..._u32(idx(tag))]));
  }

  emit(root);
  body.add(chunk(0x0101, 16, [..._u32(1), ..._u32(_none)],
      [..._u32(idx('android')), ..._u32(idx(_android))]));
  final content = [...pool, ...resmap, ...body.takeBytes()];
  return Uint8List.fromList(
      [..._u16(0x0003), ..._u16(8), ..._u32(8 + content.length), ...content]);
}

List<int> _u16(int v) => [v & 0xff, (v >> 8) & 0xff];
List<int> _u32(int v) =>
    [v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff];
