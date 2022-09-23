// Copyright 2013 The Flutter Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:meta/meta.dart';
import 'constants.dart';
import 'packet.dart';

enum RecordType {

  ///  RFC 1035[1] Address record Returns a 32-bit IPv4 address, most commonly used to map hostnames to an IP address
  ///  of the host, but it is also used for DNSBLs, storing subnet masks in RFC 1101, etc.
  A(1),

  ///  RFC 1035[1] Name server record Delegates a DNS zone to use the given authoritative name servers
  NS(2),

  ///  RFC 1035[1] Canonical name record Alias of one name to another: the DNS lookup will continue by retrying the
  ///  lookup with the new name.
  CNAME(5),

  ///  RFC 1035[1] and RFC 2308[11] Start of [a zone of] authority record Specifies authoritative information about a
  ///  DNS zone, including the primary name server, the email of the domain administrator, the domain serial number, and several timers relating to refreshing the zone.
  SOA(6),

  ///  RFC 1035[1] PTR Resource Record [de] Pointer to a canonical name. Unlike a CNAME, DNS processing stops and
  ///  just the name is returned. The most common use is for implementing reverse DNS lookups, but other uses include such things as DNS-SD.
  PTR(12),

  ///  RFC 8482 Host Information Providing Minimal-Sized Responses to DNS Queries That Have QTYPE=ANY
  HINFO(13),

  ///  RFC 1035[1] and RFC 7505 Mail exchange record Maps a domain name to a list of message transfer agents for that
  ///  domain
  MX(15),

  ///  RFC 1035[1] Text record Originally for arbitrary human-readable text in a DNS record. Since the early 1990s,
  ///  however, this record more often carries machine-readable data, such as specified by RFC 1464, opportunistic encryption, Sender Policy Framework, DKIM, DMARC, DNS-SD, etc.
  TXT(16),

  ///  RFC 1183 Responsible Person Information about the responsible person(s) for the domain. Usually an email
  ///  address with the @ replaced by a .
  RP(17),

  ///  RFC 1183 AFS database record Location of database servers of an AFS cell. This record is commonly used by AFS
  ///  clients to contact AFS cells outside their local domain. A subtype of this record is used by the obsolete DCE/DFS file system.
  AFSDB(18),

  ///  RFC 2535 Signature Signature record used in SIG(0) (RFC 2931) and TKEY (RFC 2930).[7] RFC 3755 designated
  ///  RRSIG as the replacement for SIG for use within DNSSEC.[7]
  SIG(24),

  ///  RFC 2535[3] and RFC 2930[4] Key record Used only for SIG(0) (RFC 2931) and TKEY (RFC 2930).[5] RFC 3445
  ///  eliminated their use for application keys and limited their use to DNSSEC.[6] RFC 3755 designates DNSKEY as the replacement within DNSSEC.[7] RFC 4025 designates IPSECKEY as the replacement for use with IPsec.[8]
  KEY(25),

  ///  RFC 3596[2] IPv6 address record Returns a 128-bit IPv6 address, most commonly used to map hostnames to an IP
  ///  address of the host.
  AAAA(28),

  ///  RFC 1876 Location record Specifies a geographical location associated with a domain name
  LOC(29),

  ///  RFC 2782 Service locator Generalized service location record, used for newer protocols instead of creating
  ///  protocol-specific records such as MX.
  SRV(33),

  ///  RFC 3403 Naming Authority Pointer Allows regular-expression-based rewriting of domain names which can then be
  ///  used as URIs, further domain names to lookups, etc.
  NAPTR(35),

  ///  RFC 2230 Key Exchanger record Used with some cryptographic systems (not including DNSSEC) to identify a key
  ///  management agent for the associated domain-name. Note that this has nothing to do with DNS Security. It is Informational status, rather than being on the IETF standards-track. It has always had limited deployment, but is still in use.
  KX(36),

  ///  RFC 4398 Certificate record Stores PKIX, SPKI, PGP, etc.
  CERT(37),

  ///  RFC 6672 Delegation name record Alias for a name and all its subnames, unlike CNAME, which is an alias for
  ///  only the exact name. Like a CNAME record, the DNS lookup will continue by retrying the lookup with the new name.
  DNAME(39),

  /// RFC 6891	Option	This is a pseudo-record type needed to support EDNS.
  OPT(41),

  ///  RFC 3123 Address Prefix List Specify lists of address ranges, e.g. in CIDR format, for various address
  ///  families. Experimental.
  APL(42),

  ///  RFC 4034 Delegation signer The record used to identify the DNSSEC signing key of a delegated zone
  DS(43),

  ///  RFC 4255 SSH Public Key Fingerprint Resource record for publishing SSH public host key fingerprints in the
  ///  DNS, in order to aid in verifying the authenticity of the host. RFC 6594 defines ECC SSH keys and SHA-256 hashes. See the IANA SSHFP RR parameters registry for details.
  SSHFP(44),

  ///  RFC 4025 IPsec Key Key record that can be used with IPsec
  IPSECKEY(45),

  ///  RFC 4034 DNSSEC signature Signature for a DNSSEC-secured record set. Uses the same format as the SIG record.
  RRSIG(46),

  ///  RFC 4034 Next Secure record Part of DNSSEC—used to prove a name does not exist. Uses the same format as the
  ///  (obsolete) NXT record.
  NSEC(47),

  ///  RFC 4034 DNS Key record The key record used in DNSSEC. Uses the same format as the KEY record.
  DNSKEY(48),

  ///  RFC 4701 DHCP identifier Used in conjunction with the FQDN option to DHCP
  DHCID(49),

  ///  RFC 5155 Next Secure record version 3 An extension to DNSSEC that allows proof of nonexistence for a name
  ///  without permitting zonewalking
  NSEC3(50),

  ///  RFC 5155 NSEC3 parameters Parameter record for use with NSEC3
  NSEC3PARAM(51),

  ///  RFC 6698 TLSA certificate association A record for DANE. RFC 6698 defines "The TLSA DNS resource record is
  ///  used to associate a TLS server certificate or public key with the domain name where the record is found, thus forming a 'TLSA certificate association'".
  TLSA(52),

  ///  RFC 8162[9] S/MIME cert association[10] Associates an S/MIME certificate with a domain name for sender
  ///  authentication.
  SMIMEA(53),

  ///  RFC 8005 Host Identity Protocol Method of separating the end-point identifier and locator roles of IP addresses.
  HIP(55),

  ///  RFC 7344 Child DS Child copy of DS record, for transfer to parent
  CDS(59),

  ///  RFC 7344 Child copy of DNSKEY record, for transfer to parent
  CDNSKEY(60),

  ///  RFC 7929 OpenPGP public key record A DNS-based Authentication of Named Entities (DANE) method for publishing
  ///  and locating OpenPGP public keys in DNS for a specific email address using an OPENPGPKEY DNS resource record.
  OPENPGPKEY(61),

  ///  RFC 7477 Child-to-Parent Synchronization Specify a synchronization mechanism between a child and a parent DNS
  ///  zone. Typical example is declaring the same NS records in the parent and the child zone
  CSYNC(62),

  ///  RFC 8976 Message Digests for DNS Zones Provides a cryptographic message digest over DNS zone data at rest.
  ZONEMD(63),

  ///  IETF Draft Service Binding RR that improves performance for clients that need to resolve many resources to
  ///  access a domain. More info in this IETF Draft by DNSOP Working group and Akamai technologies.
  SVCB(64),

  ///  IETF Draft HTTPS Binding RR that improves performance for clients that need to resolve many resources to
  ///  access a domain. More info in this IETF Draft by DNSOP Working group and Akamai technologies.
  HTTPS(65),

  ///  RFC 7043 MAC address (EUI-48) A 48-bit IEEE Extended Unique Identifier.
  EUI48(108),

  ///  RFC 7043 MAC address (EUI-64) A 64-bit IEEE Extended Unique Identifier.
  EUI64(109),

  ///  RFC 2930 Transaction Key record A method of providing keying material to be used with TSIG that is encrypted
  ///  under the public key in an accompanying KEY RR.[12]
  TKEY(249),

  ///  RFC 2845 Transaction Signature Can be used to authenticate dynamic updates as coming from an approved client,
  ///  or to authenticate responses as coming from an approved recursive name server[13] similar to DNSSEC.
  TSIG(250),

  ANY(255),

  ///  RFC 7553 Uniform Resource Identifier Can be used for publishing mappings from hostnames to URIs.
  URI(256),

  ///  RFC 6844 Certification Authority Authorization DNS Certification Authority Authorization, constraining
  ///  acceptable CAs for a host/domain
  CAA(257),

  ///  — DNSSEC Trust Authorities Part of a deployment proposal for DNSSEC without a signed DNS root. See the IANA
  ///  database and Weiler Spec for details. Uses the same format as the DS record.
  TA(32768),

  ///  RFC 4431 DNSSEC Lookaside Validation record For publishing DNSSEC trust anchors outside of the DNS delegation
  ///  chain. Uses the same format as the DS record. RFC 5074 describes a way of using these records.
  DLV(32769),
  ;

  final int id;
  const RecordType(this.id);

  /// Find RecordType matching the 'num'
  static RecordType find(int num) => RecordType.values.firstWhere((t) => t.id == num, orElse: (){
    print("UNKNOWN type id $num");
    return RecordType.ANY;
  });

  String toString() => '$name($id)';
}

/// Enumeration of support resource record types.
abstract class ResourceRecordType {
  // This class is intended to be used as a namespace, and should not be
  // extended directly.
  ResourceRecordType._();
}

/// Represents a DNS query.
@immutable
class ResourceRecordQuery {
  /// Creates a new ResourceRecordQuery.
  ///
  /// Most callers should prefer one of the named constructors.
  ResourceRecordQuery(
    this.resourceRecordType,
    this.fullyQualifiedName,
    this.questionType,
  );

  /// An A (IPv4) query.
  ResourceRecordQuery.addressIPv4(
    String name, {
    bool isMulticast = true,
  }) : this(
          RecordType.A,
          name,
          isMulticast ? QuestionType.multicast : QuestionType.unicast,
        );

  /// An AAAA (IPv6) query.
  ResourceRecordQuery.addressIPv6(
    String name, {
    bool isMulticast = true,
  }) : this(
          RecordType.AAAA,
          name,
          isMulticast ? QuestionType.multicast : QuestionType.unicast,
        );

  /// A PTR (Server pointer) query.
  ResourceRecordQuery.serverPointer(
    String name, {
    bool isMulticast = true,
  }) : this(
          RecordType.SRV,
          name,
          isMulticast ? QuestionType.multicast : QuestionType.unicast,
        );

  /// An SRV (Service) query.
  ResourceRecordQuery.service(
    String name, {
    bool isMulticast = true,
  }) : this(
          RecordType.SRV,
          name,
          isMulticast ? QuestionType.multicast : QuestionType.unicast,
        );

  /// A TXT (Text record) query.
  ResourceRecordQuery.text(
    String name, {
    bool isMulticast = true,
  }) : this(
          RecordType.TXT,
          name,
          isMulticast ? QuestionType.multicast : QuestionType.unicast,
        );

  /// Query for anything!
  ResourceRecordQuery.any(
      String name, {
        bool isMulticast = true,
      }) : this(
    RecordType.ANY,
    name,
    isMulticast ? QuestionType.multicast : QuestionType.unicast,
  );

  /// Tye type of resource record - one of [ResourceRecordType]'s values.
  final RecordType resourceRecordType;

  /// The Fully Qualified Domain Name associated with the request.
  final String fullyQualifiedName;

  /// The [QuestionType], i.e. multicast or unicast.
  final int questionType;

  /// Convenience accessor to determine whether the question type is multicast.
  bool get isMulticast => questionType == QuestionType.multicast;

  /// Convenience accessor to determine whether the question type is unicast.
  bool get isUnicast => questionType == QuestionType.unicast;

  /// Encodes this query to the raw wire format.
  List<int> encode() {
    return encodeMDnsQuery(
      fullyQualifiedName,
      type: resourceRecordType,
      multicast: isMulticast,
    );
  }

  @override
  int get hashCode =>
      Object.hash(resourceRecordType, fullyQualifiedName, questionType);

  @override
  bool operator ==(Object other) {
    return other is ResourceRecordQuery &&
        (other.resourceRecordType == resourceRecordType || other.resourceRecordType == RecordType.ANY ||
            resourceRecordType == RecordType.ANY) &&
        (other.fullyQualifiedName == fullyQualifiedName || other.fullyQualifiedName == '*' ||
            fullyQualifiedName == '*') &&
        other.questionType == questionType;
  }

  @override
  String toString() =>
      '$runtimeType{$fullyQualifiedName, type: $resourceRecordType, isMulticast: $isMulticast}';
}

/// Base implementation of DNS resource records (RRs).
@immutable
abstract class ResourceRecord {
  /// Creates a new ResourceRecord.
  const ResourceRecord(this.resourceRecordType, this.name, this.validUntil);

  /// The FQDN for this record.
  final String name;

  /// The epoch time at which point this record is valid for in the cache.
  final int validUntil;

  /// The raw resource record value.  See [ResourceRecordType] for supported values.
  final RecordType resourceRecordType;

  String get _additionalInfo;

  @override
  String toString() =>
      '$runtimeType {${resourceRecordType} $name, validUntil: ${DateTime.fromMillisecondsSinceEpoch(validUntil)}, '
          '$_additionalInfo}';

  @override
  int get hashCode => Object.hash(name, validUntil, resourceRecordType);

  @override
  bool operator ==(Object other) {
    return other is ResourceRecord &&
        other.name == name &&
        other.validUntil == validUntil &&
        other.resourceRecordType == resourceRecordType;
  }

  /// Low level method for encoding this record into an mDNS packet.
  ///
  /// Subclasses should provide the packet format of their encapsulated data
  /// into a `Uint8List`, which could then be used to write a pakcet to send
  /// as a response for this record type.
  Uint8List encodeResponseRecord();
}

/// A Service Pointer for reverse mapping an IP address (DNS "PTR").
class PtrResourceRecord extends ResourceRecord {
  /// Creates a new PtrResourceRecord.
  const PtrResourceRecord(
    String name,
    int validUntil, {
    required this.domainName,
  }) : super(RecordType.PTR, name, validUntil);

  /// The FQDN for this record.
  final String domainName;

  @override
  String get _additionalInfo => 'domainName: $domainName';

  @override
  int get hashCode => Object.hash(domainName.hashCode, super.hashCode);

  @override
  bool operator ==(Object other) {
    return super == other &&
        other is PtrResourceRecord &&
        other.domainName == domainName;
  }

  @override
  Uint8List encodeResponseRecord() {
    return Uint8List.fromList(utf8.encode(domainName));
  }
}

/// An IP Address record for IPv4 (DNS "A") or IPv6 (DNS "AAAA") records.
class IPAddressResourceRecord extends ResourceRecord {
  /// Creates a new IPAddressResourceRecord.
  IPAddressResourceRecord(
    String name,
    int validUntil, {
    required this.address,
  }) : super(
            address.type == InternetAddressType.IPv4
                ? RecordType.A
                : RecordType.AAAA,
            name,
            validUntil);

  /// The [InternetAddress] for this record.
  final InternetAddress address;

  @override
  String get _additionalInfo => 'address: $address';

  @override
  int get hashCode => Object.hash(address.hashCode, super.hashCode);

  @override
  bool operator ==(Object other) {
    return super == other &&
        other is IPAddressResourceRecord &&
        other.address == address;
  }

  @override
  Uint8List encodeResponseRecord() {
    return Uint8List.fromList(address.rawAddress);
  }
}

/// A Service record, capturing a host target and port (DNS "SRV").
class SrvResourceRecord extends ResourceRecord {
  /// Creates a new service record.
  const SrvResourceRecord(
    String name,
    int validUntil, {
    required this.target,
    required this.port,
    required this.priority,
    required this.weight,
  }) : super(RecordType.SRV, name, validUntil);

  /// The hostname for this record.
  final String target;

  /// The port for this record.
  final int port;

  /// The relative priority of this service.
  final int priority;

  /// The weight (used when multiple services have the same priority).
  final int weight;

  @override
  String get _additionalInfo =>
      'target: $target, port: $port, priority: $priority, weight: $weight';

  @override
  int get hashCode =>
      Object.hash(target, port, priority, weight, super.hashCode);

  @override
  bool operator ==(Object other) {
    return super == other &&
        other is SrvResourceRecord &&
        other.target == target &&
        other.port == port &&
        other.priority == priority &&
        other.weight == weight;
  }

  @override
  Uint8List encodeResponseRecord() {
    final List<int> data = utf8.encode(target);
    final Uint8List result = Uint8List(data.length + 7);
    final ByteData resultData = ByteData.view(result.buffer);
    resultData.setUint16(0, priority);
    resultData.setUint16(2, weight);
    resultData.setUint16(4, port);
    result[6] = data.length;
    return result..setRange(7, data.length, data);
  }
}

/// A Text record, contianing additional textual data (DNS "TXT").
class TxtResourceRecord extends ResourceRecord {
  /// Creates a new text record.
  const TxtResourceRecord(
    String name,
    int validUntil, {
    required this.text,
  }) : super(RecordType.TXT, name, validUntil);

  /// The raw text from this record.
  final String text;

  @override
  String get _additionalInfo => 'text: $text';

  @override
  int get hashCode => Object.hash(text.hashCode, super.hashCode);

  @override
  bool operator ==(Object other) =>
      super == other && other is TxtResourceRecord && other.text == text;

  @override
  Uint8List encodeResponseRecord() {
    return Uint8List.fromList(utf8.encode(text));
  }
}

class AnyResourceRecord extends ResourceRecord {
  Map<String, dynamic> data;
  AnyResourceRecord(super.resourceRecordType, super.name, super.validUntil, this.data);

  @override
  String get _additionalInfo => json.encode({'type': resourceRecordType.toString(), 'data': data});

  @override
  Uint8List encodeResponseRecord() {
    //todo fix this
    return Uint8List.fromList(utf8.encode(json.encode(data)));
  }

}
