---

Historical input/CPU audit. For the current hardware and GPU qualification,
see [current status](santoni-gpu-status.md).

status: candidate_code_reviewed_hardware_pending
date: 2026-10-25
review_type: manual_self_audit
base: 52e3585
candidate: d64fb2e
---

# Santoni physical-button audit

## Outcome

The button candidate and its integration checks pass. **Actual power/volume
operation and touch recovery remain unverified on the phone.** This is a manual
self-audit, not independent approval; the independent-review provider was
unavailable during the preceding touch stage.

Order followed: touch candidate `c692ebd` → touch audit `52e3585` → button
candidate `d64fb2e` → this button audit. The user requested one combined build.

## Hardware mapping checked

| Button | Santoni source | Event sent |
|---|---|---|
| Power | PM8937 SID 0, PON RT_STS `0x0810`, bit 0 | Consumer Power `0x30`, key 0 |
| Volume Up | TLMM GPIO91, input pull-up, active low | Consumer Volume Increment `0xe9`, key 1 |
| Volume Down | Same PON byte, RESIN bit 1 | Consumer Volume Decrement `0xea`, key 2 |

References: `pm8937.dtsi:40–67`, `msm8940-xiaomi-santoni.dts:98–109,261–264,
494–499`, `pm8941-pwrkey.c:33–36,164–185,423–443`. Sailfish 0089 confirms the
PON observer/read mechanism, **not** Santoni GPIO addresses or the desired key
mapping. Sailfish's Volume Down is intentionally Home; Santoni does not copy it.

## Audited fixes and integration

1. **Missing power input:** 0170 reads KPDPWR independently of RESIN. Both bits
   can be pressed together; their debounce states do not alias.
2. **Polling coupling:** 0172 starts a separate button thread before the touch
   thread. It maps only the GPIO91 tile and never changes SDA/SCL/reset/INT.
   Touch probing, reset waits and long RPM retries no longer suspend key
   polling. The touch loop no longer performs PON reads between touch reports.
3. **Concurrency introduced by that split:** all lazy APID/observer maps and
   whole observer transactions go through `santoni_spmi_lock`. The internal
   `_locked` routine is called only by the locking wrapper. Success/error
   returns release the mutex; there is no new interrupt-context caller.
   The declaration style matches the existing kernel SDHCI mutex.
4. **Presses lost before HID registration:** raw/stable state is tracked while
   clients are absent, but a press is not consumed until the button HID service
   has clients. A key held at initial attachment is delivered once ready.
5. **Cross-thread service publication:** the initialized button/touch singleton
   pointers are release-published and acquire-loaded by their entry points and
   the optional test timer. The physical digitizer construction and coordinate
   method remain byte-identical to the working post-0165 source.
6. **Unwanted Home input:** neither volume key sends key 3/Menu. The optional
   test timer still emits no Home keys, has a four-swipe cap and yields to
   physical input. It is not proof that the lock screen is ready.
7. **PMIC safety:** only the observer command/status/data path is used; no PON
   pull/reset/enable/ack register is programmed. A failed read does not create
   a fake power/Volume-Down release. Volume Up remains independent of PMIC read
   success. The timeout uses 0169's short busy waits, not scheduler sleeps.

## Tests actually run

`HOST_CC=clang HOST_CXX=clang++ OUT_DIR=out/santoni-button-audit-final bash tests/run_tests.sh`

- **75/75** actual input/RPM cases: all three key usages, simultaneous presses,
  bounce/release, unreadable/stalled PON, delayed HID readiness, both startup
  callbacks, polling isolation and mutex release on failure, plus preserved
  I2C/report/RPM coverage.
- **9/9** actual HID/display cases, including the new readiness entry point.
- **128/128** GIC/SMP, **3/3** idle policy, **10/10** fake-ADB extraction checks.
- Storage/logging, all patch structure/applicability gates: passed.
- Input **75/75** and HID/display **9/9** also passed ASan/UBSan.
- Pre-0170 sources fail the three new power cases. Pre-0172 sources fail all
  five polling-isolation/readiness/startup/mutex cases. They were not relaxed
  to hide the baseline failures.

The host mutex fixture checks placement/release and protected MMIO calls; it
does not simulate all real concurrent schedules. Client presence is a mocked
condition, not proof of backboardd's runtime consumption. Kernel headers/linking
and actual firmware access must still pass CI and the device test.

## Remaining hardware gate

- Verify taps, drags, releases and unlock using actual fingers.
- Verify short power presses reach iOS lock/wake and each volume key has only
  its expected effect. `sweetfb_stayon=1` intentionally keeps the panel lit;
  a lit screen alone is not evidence that the power event was ignored.
- The built-in services are treated as permanent bring-up singletons; these
  changes do not add general driver hot-detach/unload support.
- If eight-core input still fails, use the saved same-kernel four-core image
  and SYSTEM log rather than assuming host tests establish the failure cause.
- Preserve the exact working 0165 image. GPU implementation must remain off
  until physical touch, Power, Volume Up and Volume Down are confirmed.

## Post-audit build verification

Kernel headers/linking and all workflow gates passed CI **40170676997** for
`cc215ac`. The compiled button/readiness symbols are present; disassembly
confirms the PMIC lock/unlock path and HID acquire load. Kernel SHA256:
`4e4054089f3ff47cb43204f319263df1120f63b8a548c05adf8b652ff36c9f65`.
This resolves the CI gate, **not** the outstanding physical-button/touch test.
