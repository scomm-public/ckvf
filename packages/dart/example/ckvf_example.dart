import 'package:ckvf/ckvf.dart';

Future<void> main() async {
  final canonical = jcs({'b': 1, 'a': 2});
  if (canonical != '{"a":2,"b":1}') {
    throw StateError('JCS');
  }
}
