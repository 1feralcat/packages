import 'dart:io';
import 'dart:typed_data';

import 'package:multicast_dns/multicast_dns.dart';
import 'package:multicast_dns/src/packet.dart';
import 'package:test/test.dart';

void main() {
  test('Can encode valid packets', () {
    testEncodePtr();
    testEncodeSrv();
    testEncodeTxt();
  });
}

void testEncodeSrv() {
  final SrvResourceRecord record = SrvResourceRecord(
    '_test._tcp.local',
    DateTime.now().add(const Duration(days: 1)).millisecondsSinceEpoch,
    target: 'target.test.local',
    port: 99,
    priority: 88,
    weight: 77,
  );
  final List<int> packet = ResourceRecordQuery.serverPointer("test").encodeRecord(record);
  final List<ResourceRecord> records = decodeMDnsResponse(packet);
  expect(records.length, 1);
  final SrvResourceRecord result = records[0] as SrvResourceRecord;
  expect(result.port, record.port);
  expect(result.priority, record.priority);
  expect(result.weight, record.weight);
  expect(result.target, record.target);

  // Test sending the packet - only works only for this multicast_dns plugin
  // RawDatagramSocket.bind(InternetAddress.anyIPv4, 0).then((RawDatagramSocket socket){
  //   socket.send(packet, mDnsAddressIPv4, mDnsPort);
  // });
  }
void testEncodeTxt() {
  final TxtResourceRecord record = TxtResourceRecord('_test._tcp.local',
      DateTime.now().add(const Duration(days: 1)).millisecondsSinceEpoch,
      text: ["multiline text string"]);
  final List<int> packet = ResourceRecordQuery.text("test").encodeRecord(record);
  final List<ResourceRecord> records = decodeMDnsResponse(packet);
  expect(records.length, 1);
  final TxtResourceRecord result = records[0] as TxtResourceRecord;
  expect(result.text, record.text);
}

void testEncodePtr() {
  final PtrResourceRecord record = PtrResourceRecord('test.local',
      DateTime.now().add(const Duration(days: 1)).millisecondsSinceEpoch,
      domainName: '_cuden._tcp.local');
  final List<int> packet = ResourceRecordQuery.text("test").encodeRecord(record);
  final List<ResourceRecord> records = decodeMDnsResponse(packet);
  expect(records.length, 1);
  final PtrResourceRecord result = records[0] as PtrResourceRecord;
  expect(result.domainName, record.domainName);
}