@TestOn('vm')
library;

import 'package:risaal_crypto/risaal_crypto.dart';
import 'package:test/test.dart';

/// Generation retirement.
///
/// The keyring is capped at eight generations and had no retirement at all: on
/// the ninth rotation the device threw `Key-bundle generation keyring capacity
/// reached` and could **never rotate or replenish its one-time pre-keys again**.
/// For someone who suspects their key is compromised, that is the control which
/// replaces a key ceasing to exist — and it arrives on its own through ordinary
/// replenishment, with no attacker involved.
///
/// The opposite error is worse per message: dropping a generation that a
/// server-deliverable envelope can still target loses that message forever. Both
/// directions are pinned here.
void main() {
  final now = DateTime.utc(2026, 8, 12);

  GenerationRetirementView view(
    int id,
    OpkGenerationRole role, {
    Duration? demotedAgo,
  }) => (
    opkGeneration: id,
    role: role,
    demotedAtMillis: demotedAgo == null
        ? null
        : now.subtract(demotedAgo).millisecondsSinceEpoch,
  );

  List<GenerationRetirementView> keyring({
    required int retained,
    Duration? demotedAgo,
  }) => [
    for (var i = 1; i <= retained; i++)
      view(i, OpkGenerationRole.retainedLookupOnly, demotedAgo: demotedAgo),
    view(retained + 1, OpkGenerationRole.acceptedLookupOnly),
  ];

  test('a full keyring of ancient generations can make room', () {
    final generations = keyring(
      retained: 7,
      demotedAgo: const Duration(days: 90),
    );
    final retirable = retirableGenerationIds(
      generations: generations,
      now: now,
    );

    expect(retirable, isNotEmpty, reason: 'otherwise rotation is impossible');
    expect(
      generations.length - retirable.length,
      GenerationRetirementPolicy.minimumRetained,
    );
  });

  test('the accepted generation is never retired', () {
    final generations = keyring(
      retained: 7,
      demotedAgo: const Duration(days: 90),
    );
    expect(
      retirableGenerationIds(generations: generations, now: now),
      isNot(contains(8)),
      reason: 'retiring the current key destroys the ability to be contacted',
    );
  });

  test('a staged generation is never retired', () {
    final generations = [
      for (var i = 1; i <= 6; i++)
        view(
          i,
          OpkGenerationRole.retainedLookupOnly,
          demotedAgo: const Duration(days: 90),
        ),
      view(7, OpkGenerationRole.stagedUploadOnly),
      view(8, OpkGenerationRole.acceptedLookupOnly),
    ];
    final retirable = retirableGenerationIds(
      generations: generations,
      now: now,
    );
    expect(retirable, isNot(contains(7)));
    expect(retirable, isNot(contains(8)));
  });

  test('a legacy-quarantined record is evidence, not a retirable key', () {
    final generations = [
      view(0, OpkGenerationRole.legacyQuarantined),
      for (var i = 1; i <= 6; i++)
        view(
          i,
          OpkGenerationRole.retainedLookupOnly,
          demotedAgo: const Duration(days: 90),
        ),
      view(7, OpkGenerationRole.acceptedLookupOnly),
    ];
    expect(
      retirableGenerationIds(generations: generations, now: now),
      isNot(contains(0)),
    );
  });

  test('a recently demoted generation is not retired', () {
    expect(
      retirableGenerationIds(
        generations: keyring(retained: 7, demotedAgo: const Duration(days: 1)),
        now: now,
      ),
      isEmpty,
      reason:
          'a sender who fetched the bundle yesterday may not come online for '
          'weeks, and a PreKey envelope can target the signed-prekey and KEM '
          'key with no one-time key at all',
    );
  });

  test('the boundary is inclusive at exactly the grace window', () {
    expect(
      retirableGenerationIds(
        generations: keyring(
          retained: 7,
          demotedAgo: GenerationRetirementPolicy.grace,
        ),
        now: now,
      ),
      isNotEmpty,
    );
    expect(
      retirableGenerationIds(
        generations: keyring(
          retained: 7,
          demotedAgo:
              GenerationRetirementPolicy.grace - const Duration(seconds: 1),
        ),
        now: now,
      ),
      isEmpty,
    );
  });

  test('an unknown demotion time is never retired on age', () {
    expect(
      retirableGenerationIds(generations: keyring(retained: 7), now: now),
      isEmpty,
      reason:
          'journals written before retirement existed carry no timestamp; the '
          'age is unknown, so it is stamped at first sight rather than guessed',
    );
  });

  test('a demotion stamped in the future is not retired', () {
    // A device whose clock jumped backwards, or a tampered record. Treating a
    // future timestamp as "very old" would retire a live generation.
    expect(
      retirableGenerationIds(
        generations: keyring(
          retained: 7,
          demotedAgo: const Duration(days: -365),
        ),
        now: now,
      ),
      isEmpty,
    );
  });

  test('the longest-unreachable generation goes first', () {
    final generations = [
      view(
        1,
        OpkGenerationRole.retainedLookupOnly,
        demotedAgo: const Duration(days: 400),
      ),
      view(
        2,
        OpkGenerationRole.retainedLookupOnly,
        demotedAgo: const Duration(days: 200),
      ),
      view(
        3,
        OpkGenerationRole.retainedLookupOnly,
        demotedAgo: const Duration(days: 100),
      ),
      view(4, OpkGenerationRole.acceptedLookupOnly),
    ];
    expect(retirableGenerationIds(generations: generations, now: now), [
      1,
    ], reason: 'only one may go while three must remain');
  });

  test('the minimum holds even when everything is ancient', () {
    final generations = [
      for (var i = 1; i <= 3; i++)
        view(
          i,
          OpkGenerationRole.retainedLookupOnly,
          demotedAgo: const Duration(days: 3650),
        ),
    ];
    expect(retirableGenerationIds(generations: generations, now: now), isEmpty);
  });

  test('the grace window is long enough to outlive a queued sender', () {
    expect(
      GenerationRetirementPolicy.grace,
      greaterThanOrEqualTo(const Duration(days: 30)),
      reason:
          'a sender who fetched a bundle and went offline must still be able '
          'to reach this device when they come back',
    );
  });
}
