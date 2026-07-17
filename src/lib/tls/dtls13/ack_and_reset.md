# DTLS 1.3 final ACK test

## User

Look through the available BoringSSL BoGo tests in build_deps/boringssl/ssl/test/runner and find a test that verifies the DTLS client's proper handling of the mandated final ACK record a DTLS 1.3 server has to issue in response to the client's final Finished.

I would like to implement this handling in our work-in-progress Botan DTLS 1.3 implementation and need some acceptence test for it.

## Assistant

I'll search the BoGo test runner for tests related to the final ACK in DTLS 1.3.

### Tool Ripgrep Raw Search

```
{"pattern":"ACK","path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/test/runner","outputMode":"files_with_matches","caseInsensitive":false,"multiline":false,"toolCallId":"Grep_0_16acf33b-7b611","offset":0}
```

### Tool Ripgrep Raw Search

```
{"pattern":"final ACK|finalAck|FinalACK","path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/test/runner","outputMode":"content","caseInsensitive":true,"multiline":false,"toolCallId":"Grep_1_b9a7f800-7b611","offset":0}
```

### Tool Ripgrep Raw Search

```
{"pattern":"ACK","path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/test/runner/dtls_tests.go","outputMode":"content","caseInsensitive":false,"multiline":false,"toolCallId":"Grep_0_d52c34d1-7b612","offset":0}
```

### Tool Ripgrep Raw Search

```
{"pattern":"ACK","path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/test/runner/handshake_client.go","outputMode":"content","caseInsensitive":false,"multiline":false,"toolCallId":"Grep_1_7d95d617-7b612","offset":0}
```

## Assistant

Let me look at the most relevant test sections in detail.

### Tool Read File V2

```
{"path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/test/runner/dtls_tests.go","offset":1115,"limit":180}
```

### Tool Read File V2

```
{"path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/test/runner/handshake_client.go","offset":1560,"limit":80}
```

## Assistant

Let me look at the default ACK flight handling and where `expectedACK` is set.

### Tool Read File V2

```
{"path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/test/runner/dtls_tests.go","offset":100,"limit":220}
```

### Tool Ripgrep Raw Search

```
{"pattern":"expectedACK","path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/test/runner","outputMode":"content","caseInsensitive":false,"multiline":false,"toolCallId":"Grep_1_2f7b4d88-7b614","offset":0}
```

## Assistant

Let me look at the runner's default ACK behavior in `dtls.go` and how the final flight ACK is driven.

### Tool Read File V2

```
{"path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/test/runner/dtls.go","offset":700,"limit":130}
```

### Tool Read File V2

```
{"path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/test/runner/dtls.go","offset":1030,"limit":90}
```

### Tool Ripgrep Raw Search

```
{"pattern":"ACKFlightDTLS|WriteFlightDTLS","path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/test/runner","glob":"!dtls_tests.go","outputMode":"content","caseInsensitive":false,"multiline":false,"toolCallId":"Grep_0_ab30856e-7b616","offset":0}
```

### Tool Read File V2

```
{"path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/test/runner/dtls.go","offset":420,"limit":100}
```

## Assistant

Let me check the version naming so I can give you the exact test names, and look at how Botan's BoGo shim/config is set up to run these.

### Tool Ripgrep Raw Search

```
{"pattern":"VersionDTLS13|DTLS13|dtls13","path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/test/runner/common.go","outputMode":"content","caseInsensitive":false,"headLimit":20,"multiline":false,"toolCallId":"Grep_0_6ac9bcdf-7b618","offset":0}
```

### Tool Ripgrep Raw Search

```
{"pattern":"bogo|BoGo|runner","path":"/home/meusel/Projects/botan/src/scripts","outputMode":"files_with_matches","caseInsensitive":true,"multiline":false,"toolCallId":"Grep_1_f2138602-7b618","offset":0}
```

### Tool Read File V2

```
{"path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/test/runner/common.go","offset":40,"limit":70}
```

### Tool Ripgrep Raw Search

```
{"pattern":"name:\\s+\"DTLS","path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/test/runner","outputMode":"content","caseInsensitive":false,"multiline":false,"toolCallId":"Grep_0_69b10ca7-7b6110","offset":0}
```

### Tool Ripgrep Raw Search

```
{"pattern":"\"DTLS13\"|\"DTLS12\"","path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/test/runner/runner.go","outputMode":"content","caseInsensitive":false,"headLimit":10,"multiline":false,"toolCallId":"Grep_0_2ab2e235-7b6111","offset":0}
```

### Tool Ripgrep Raw Search

```
{"pattern":"func allVersions|name:.*DTLS|vers.name","path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/test/runner","glob":"!dtls_tests.go","outputMode":"content","caseInsensitive":false,"headLimit":30,"multiline":false,"toolCallId":"Grep_0_3dad7df9-7b6112","offset":0}
```

### Tool Read File V2

```
{"path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/test/runner/runner.go","offset":2000,"limit":100}
```

## Assistant

Let me check how Botan integrates with BoGo, since these tests have specific shim requirements.

### Tool Glob File Search

```
{"globPattern":"**/bogo*"}
```

### Tool Ripgrep Raw Search

```
{"pattern":"bogo|boringssl","path":"/home/meusel/Projects/botan/src/scripts/ci_build.py","outputMode":"content","caseInsensitive":true,"headLimit":20,"multiline":false,"toolCallId":"Grep_1_dca3045e-7b6114","offset":0}
```

### Tool Ripgrep Raw Search

```
{"pattern":"async|dtls|DTLS","path":"/home/meusel/Projects/botan/src/bogo_shim/bogo_shim.cpp","outputMode":"content","caseInsensitive":false,"headLimit":40,"multiline":false,"toolCallId":"Grep_0_0aa2ffb6-7b6115","offset":0}
```

### Tool Glob File Search

```
{"globPattern":"src/bogo_shim/*"}
```

## Assistant

I found the relevant tests. Here's the full picture.

## The test you're looking for: `DTLS-Retransmit-Client-TLS13`

The most direct acceptance test is in `build_deps/boringssl/ssl/test/runner/dtls_tests.go`. When BoGo's runner plays the **server** and your implementation is the client, the runner's `ACKFlightDTLS` callback fires exactly when it has received the client's final Finished flight — i.e., the point where RFC 9147 mandates the server respond with an ACK:

```1130:1195:build_deps/boringssl/ssl/test/runner/dtls_tests.go
			testCases = append(testCases, testCase{
				protocol: dtls,
				name:     "DTLS-Retransmit-Client" + suffix,
				config: Config{
					MaxVersion: vers.version,
					// Require a client certificate, so the Finished flight
					// is large.
					ClientAuth: RequireAnyClientCert,
					Bugs: ProtocolBugs{
						SendHelloRetryRequestCookie: []byte("cookie"), // Send HelloRetryRequest
						MaxPacketLength:             512,
// ...
						ACKFlightDTLS: func(c *DTLSController, prev, received []DTLSMessage, records []DTLSRecordNumberInfo) {
							// The shim will process application data without an ACK.
							msg := []byte("hello")
							c.WriteAppData(c.OutEpoch(), msg)
							c.ReadAppData(c.InEpoch(), expectedReply(msg))

							// After a timeout, the shim will retransmit Finished.
							c.AdvanceClock(useTimeouts[0])
							c.ReadRetransmit()
// ...
							// ACK part of the flight and check that retransmits
							// are updated.
							c.WriteACK(c.OutEpoch(), records[len(records)/3:2*len(records)/3])
							c.AdvanceClock(useTimeouts[1])
							records = c.ReadRetransmit()

							// ACK the rest. Retransmits should stop.
							c.WriteACK(c.OutEpoch(), records)
							for _, t := range useTimeouts[2:] {
								c.AdvanceClock(t)
							}
						},
```

This verifies client-side ACK handling in three steps:
1. **ACK withheld** — the client must keep its retransmit timer armed and retransmit the Finished flight after the timeout, even while application data flows.
2. **Partial ACK** — the client must consume the ACK record and narrow its retransmission to only the un-ACKed records.
3. **Final ACK** — after ACKing the rest, the clock is advanced through all remaining timeouts; any further retransmit from the client would desync the subsequent test-message exchange and fail the test. This proves the client processed the final ACK and stopped its retransmit timer.

## Supporting tests worth using as acceptance criteria

- **`DTLS-Retransmit-Client-Basic-TLS13`** (`dtls_tests.go:199`) with `ackFlightBasic` — the simpler variant: the client must retransmit its final flight through every timeout until the runner finally sends the ACK:

```176:190:build_deps/boringssl/ssl/test/runner/dtls_tests.go
		ackFlightBasic := handleNewSessionTicket(func(c *DTLSController, prev, received []DTLSMessage, records []DTLSRecordNumberInfo) {
			if vers.version >= VersionTLS13 {
				// In DTLS 1.3, final flights (either handshake or post-handshake)
				// are retransmitted until ACKed. Exercise every timeout but
				// the last one (which would fail the connection).
				for _, t := range useTimeouts[:len(useTimeouts)-1] {
					c.ExpectNextTimeout(t)
					c.AdvanceClock(t)
					c.ReadRetransmit()
				}
				c.ExpectNextTimeout(useTimeouts[len(useTimeouts)-1])
				// Finally ACK the flight.
				c.WriteACK(c.OutEpoch(), records)
				return
			}
```

- **`DTLS-Retransmit-Client-FinishedTimeout-TLS13`** (`dtls_tests.go:1199`) — the negative counterpart: the server never sends the final ACK, so the client must keep retransmitting and eventually fail with `:READ_TIMEOUT_EXPIRED:` (which your shim already maps at `src/bogo_shim/bogo_shim.cpp:176`).

- **`DTLS-Retransmit-Client-NoImplictACKFinished-TLS13`** (`dtls_tests.go:1223`) — verifies the client does *not* treat NewSessionTicket, KeyUpdate, or application data as an implicit ACK of its Finished flight, and only stops retransmitting on the explicit ACK (ends with `c.ExpectNoNextTimeout()`).

## Mechanism notes

- By default (no `ACKFlightDTLS` override), the runner-as-server sends the mandated final ACK automatically in `dtlsACKHandshake`:

```495:501:build_deps/boringssl/ssl/test/runner/dtls.go
	if c.config.Bugs.ACKFlightDTLS != nil {
		c.config.Bugs.ACKFlightDTLS(&controller, prev, received, records)
	} else {
		if c.vers.protocolVersion() >= VersionTLS13 {
			controller.WriteACK(controller.OutEpoch(), records)
		}
	}
```

  So every DTLS 1.3 client test implicitly requires your client to *tolerate* the ACK, but only the retransmit tests above *verify* it is handled correctly.

- The mirror image (runner-as-client checking that a *server* shim sends the final ACK) lives at `handshake_client.go:1605-1609`, where the runner's own client explicitly reads the expected ACK record after sending Finished.

- The DTLS 1.3 variants carry the `-TLS13` suffix because the version table (`runner.go:2069-2077`) names the DTLS-1.3-capable entry "TLS13". Each test also exists in a `-Short` variant with 250ms initial timeouts.

- All of these require the shim's `-async` mode with the runner-controlled virtual clock (`AdvanceClock`). Your shim already advertises `async` (`src/bogo_shim/bogo_shim.cpp:853`) and implements the virtual DTLS timer (`bogo_shim.cpp:2164-2169`, `:2303-2313`), so they should be runnable once your client handles the ACK.

If you want a minimal starting point, I'd suggest `DTLS-Retransmit-Client-Basic-TLS13` first (pure "retransmit until ACKed, then stop"), then `DTLS-Retransmit-Client-TLS13` (partial ACKs interleaved with app data), with `DTLS-Retransmit-Client-FinishedTimeout-TLS13` as the negative test.

## User

I'm trying to understand the first test "DTLS-Retransmit-Client-TLS13", and it mandates that the ACKs in response to the shim's ClientHello shall be ignored, see
```/home/meusel/Projects/botan/build_deps/boringssl/ssl/test/runner/dtls_tests.go:1122:1125
				// As a client, the shim must tolerate ACKs in response to its
				// initial ClientHello, but it will not process them because the
				// version is not yet known. The second ClientHello, in response
				// to HelloRetryRequest, however, is ACKed.
```
 .

Does the RFC mandate that, or is that a design decision of boringssl?

## Assistant

Good question — let me check both the RFC text and BoringSSL's own implementation comments to answer precisely.

### Tool Ripgrep Raw Search

```
{"pattern":"version is not yet known|version.{0,40}not.{0,20}known|ACK.{0,80}version","path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl","glob":"*.cc","outputMode":"content","caseInsensitive":true,"headLimit":30,"multiline":false,"toolCallId":"Grep_0_461df1f9-c78c1","offset":0}
```

### Tool Web Fetch

```
{"url":"https://www.rfc-editor.org/rfc/rfc9147#section-7","toolCallId":"WebFetch_1_d7a644f4-c78c1"}
```

## Assistant

The RFC fetch gave me Section 7. Now let me look at BoringSSL's own implementation comments, which the grep found.

### Tool Read File V2

```
{"path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/d1_pkt.cc","offset":20,"limit":80}
```

### Tool Read File V2

```
{"path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/d1_both.cc","offset":810,"limit":60}
```

## Assistant

Short answer: **it's a BoringSSL design decision — but one the RFC's text strongly invites, and which BoGo effectively enforces.** RFC 9147 never explicitly says "clients MUST ignore ACKs received before version negotiation." Let me break down what the RFC does and doesn't say.

## What RFC 9147 actually says

**The RFC creates the situation, but doesn't prescribe the client's behavior in it.** Section 7.1 recommends that a receiver ACK a partial flight:

> "When an implementation detects a disruption in the receipt of the current incoming flight, it SHOULD generate an ACK... When they have received part of a flight and do not immediately receive the rest of the flight..."

So a DTLS 1.3 server that receives a fragmented ClientHello may legitimately send an ACK for it — and at that point the client has not yet seen a ServerHello/HelloRetryRequest, i.e., it doesn't know whether the connection will be DTLS 1.3 (where content type 26 is defined) or DTLS 1.2 (where it isn't). The RFC is silent on what the client should do with such an ACK. Section 7.2 ("Receiving ACKs") describes ACK processing but contains no pre-version-negotiation rule.

**Two RFC provisions do support the "tolerate" part:**

- The general record-layer robustness rule (§4.5.2): *"In general, invalid records SHOULD be silently discarded, thus preserving the association."* Aborting the handshake on a syntactically valid ACK record would be an interoperability bug, since a compliant server can send one.
- Implicit acknowledgement (§7.2): *"the receipt of any record responding to a given flight MUST be taken as an implicit acknowledgement for the entire flight to which it is responding."* The ClientHello flight is always implicitly ACKed by the server's responding flight (HRR or ServerHello), so ignoring the explicit pre-version ACK costs nothing in correctness — worst case the client retransmits the whole ClientHello once.

## What BoringSSL decided

The BoGo comment mirrors BoringSSL's own implementation almost verbatim:

```35:51:build_deps/boringssl/ssl/d1_pkt.cc
ssl_open_record_t dtls1_process_ack(SSL *ssl, uint8_t *out_alert,
                                    DTLSRecordNumber ack_record_number,
                                    Span<const uint8_t> data) {
  // As a DTLS-1.3-capable client, it is possible to receive an ACK before we
  // receive ServerHello and learned the server picked DTLS 1.3. Thus, tolerate
  // but ignore ACKs before the version is set.
  if (!ssl_has_final_version(ssl)) {
    return ssl_open_record_discard;
  }

  // ACKs are only allowed in DTLS 1.3. Reject them if we've negotiated a
  // version and it's not 1.3.
  if (ssl_protocol_version(ssl) < TLS1_3_VERSION) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_RECORD);
    *out_alert = SSL_AD_UNEXPECTED_MESSAGE;
    return ssl_open_record_error;
  }
```

The rationale for *ignoring* rather than *processing*: until the ServerHello/HRR arrives, the server might still pick DTLS 1.2, where the ACK is meaningless — so the ACK's semantics are undefined at that point. Once HRR is received, the version *is* known (HRR carries `supported_versions`), which is why the BoGo comment says the second ClientHello "however, is ACKed" — those ACKs are processed normally.

## The catch: BoGo enforces it anyway

While the RFC doesn't mandate ignore-before-version, the test you're working with effectively does. In the `WriteFlightDTLS` hook, the runner ACKs the first ClientHello's record and then requires the retransmission to be unaffected:

```1151:1163:build_deps/boringssl/ssl/test/runner/dtls_tests.go
				if len(prev) == 0 {
					// This is HelloRetryRequest in response to ClientHello1. The client
					// will accept the ACK, but it will ignore it. Do not expect
					// retransmits to be impacted.
					first.MessageStartSequence = 0
					first.MessageStartOffset = 0
					first.MessageEndSequence = 0
					first.MessageEndOffset = 0
				}
				c.WriteACK(0, []DTLSRecordNumberInfo{first})
				c.AdvanceClock(useTimeouts[0])
				c.ReadRetransmit()
```

If your client *processed* that ACK and omitted the ACKed record from its retransmission (and ClientHello1 typically fits in one record, so it would retransmit nothing), `ReadRetransmit()` would fail. So for BoGo compatibility, Botan's client should:

1. **Before the version is known** (no ServerHello/HRR processed): accept ACK records and silently discard them — don't error, don't match them against the retransmission queue.
2. **Once DTLS 1.3 is negotiated**: process ACKs normally.
3. **Once a version < 1.3 is negotiated**: treat an ACK record as an error (BoringSSL sends `unexpected_message`).

So: not RFC-mandated, but RFC-permitted server behavior (§7.1) plus DTLS's discard-don't-abort philosophy (§4.5.2) make "tolerate but ignore" the interoperable choice, and BoGo's `DTLS-Retransmit-Client-TLS13` will hold you to it.

## User

The same happens after we received the HelloRetryRequest from the BoGo-server. I mirrored the behavior you described for the initial ACKs and stopped ignoring them after receiving the HRR and re-sending the ClientHello (with the cookie extension of the HRR).

Again, BoGo complains that I re-sent the un-ACKed records immediately after receiving an unprotected ACK that acknowledges the first record of our second ClientHello flight. What's the expected behavior?

## Assistant

Let me look at what BoringSSL does after processing a partial ACK, and at the runner's `ReadRetransmit`/`AdvanceClock` expectations.

### Tool Read File V2

```
{"path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/d1_pkt.cc","offset":96,"limit":80}
```

### Tool Ripgrep Raw Search

```
{"pattern":"func \\(c \\*DTLSController\\) (ReadRetransmit|AdvanceClock|WriteACK|ExpectNextTimeout|ExpectNoNextTimeout)","path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/test/runner/dtls.go","outputMode":"content","caseInsensitive":false,"multiline":false,"toolCallId":"Grep_1_474f4f8c-ea198","offset":0}
```

## Assistant

Now let me look at the runner's `AdvanceClock` and `ReadRetransmit` to see exactly what the test expects.

### Tool Read File V2

```
{"path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/test/runner/dtls.go","offset":945,"limit":75}
```

### Tool Read File V2

```
{"path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/test/runner/dtls.go","offset":1159,"limit":130}
```

## Assistant

Let me check the packet adaptor's `SendReadTimeout` to understand how the runner detects premature retransmission.

### Tool Ripgrep Raw Search

```
{"pattern":"SendReadTimeout|func .*packetAdaptor|opcode","path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/test/runner/packet_adapter.go","outputMode":"content","caseInsensitive":false,"multiline":false,"toolCallId":"Grep_0_4b14915b-ea1910","offset":0}
```

### Tool Read File V2

```
{"path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/test/runner/packet_adapter.go","offset":100,"limit":50}
```

## Assistant

Let me check how BoringSSL's own shim handles the timeout opcode, to understand the expected ordering.

### Tool Ripgrep Raw Search

```
{"pattern":"opcodeTimeout|case 'T'|'t'","path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/test","glob":"*.cc","outputMode":"content","caseInsensitive":false,"headLimit":30,"multiline":false,"toolCallId":"Grep_0_cca0bdab-ea1913","offset":0}
```

### Tool Read File V2

```
{"path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/test/packeted_bio.cc"}
```

## Assistant

Now I have the complete picture of the mechanism. Let me also check whether the RFC update mentioned in the fetch (RFC 9853) is relevant here.

### Tool Web Search

```
{"searchTerm":"RFC 9853 DTLS 1.3 update ACK retransmission","toolCallId":"WebSearch_0_7fdb2e66-ea1915"}
```

## Assistant

## Expected behavior: prune the retransmit queue, send nothing, keep the timer running

On receiving a **partial** ACK, your client should:

1. Mark the ACKed records/fragments as acknowledged (remove them from the retransmission queue).
2. **Send nothing in response.** Leave the retransmit timer untouched.
3. When the timer next expires, retransmit only the still-unacknowledged records.
4. Only when an ACK covers the *entire* flight do you cancel the retransmit timer (and, for the final flight, consider the handshake done).

Your immediate retransmission upon ACK receipt is exactly what BoGo rejects. Here's why.

## How BoGo detects it

The retransmit tests run the shim in `-async` mode, where the runner owns the clock. `AdvanceClock` sends a `T` opcode and then **requires silence** until the shim acknowledges it:

```945:961:build_deps/boringssl/ssl/test/runner/dtls.go
func (c *DTLSController) AdvanceClock(duration time.Duration) {
// ...
	received, err := adaptor.SendReadTimeout(duration)
	if err != nil {
		c.err = err
	} else if len(received) != 0 {
		c.err = fmt.Errorf("tls: received %d unexpected packets while simulating a timeout", len(received))
	}
}
```

`SendReadTimeout` buffers any shim packets that arrive before the shim's timeout-acknowledgement (`t` opcode) and returns them — non-empty means failure (`packet_adapter.go:111-144`). BoringSSL's shim satisfies this by ACKing the `T` opcode *immediately* and only then advancing the virtual clock and calling `DTLSv1_handle_timeout` via a deferred interrupt, so the retransmission happens strictly *after* the acknowledgement (`packeted_bio.cc:137-157` and `:339-357`).

Since your client retransmits as soon as it processes the ACK record, those packets land in the runner's timeout-simulation window and you get "received N unexpected packets while simulating a timeout".

After the clock advance, `ReadRetransmit` then expects *exactly* the un-ACKed remainder — `WriteACK` has already removed the ACKed fragments from `c.retransmitNeeded` (`dtls.go:1177-1221`), and `doReadRetransmit` matches fragments one-for-one.

## What BoringSSL does on partial ACK

This mirrors its implementation — full ACK stops the timer; partial ACK only prunes, with a TODO noting an *earlier* (but still timer-scheduled) retransmit would be a possible optimization:

```122:154:build_deps/boringssl/ssl/d1_pkt.cc
  // If the outgoing flight is now fully ACKed, we are done retransmitting.
  if (std::all_of(ssl->d1->outgoing_messages.begin(),
                  ssl->d1->outgoing_messages.end(),
                  [](const auto &msg) { return msg.IsFullyAcked(); })) {
    dtls1_stop_timer(ssl);
    dtls_clear_outgoing_messages(ssl);
// ...
  } else {
    // We may still be able to drop unused write epochs.
    dtls_clear_unused_write_epochs(ssl);

    // TODO(crbug.com/383016430): Schedule a retransmit. The peer will have
    // waited before sending the ACK, so a partial ACK suggests packet loss.
  }
```

## RFC vs. BoringSSL, again

Here your implementation is actually closer to the RFC text than BoringSSL is. RFC 9147 §5.8.1 (state machine, exit 2 from WAITING) says:

> "upon receiving an ACK for a partial flight ..., the implementation transitions to the SENDING state, where it retransmits the unacknowledged portion of the flight, adjusts and re-arms the retransmit timer"

and §7.2: "an implementation SHOULD retransmit the unacknowledged messages or fragments."

So immediate retransmission on partial ACK is a SHOULD-level behavior in the RFC — but BoringSSL deliberately doesn't do it, and BoGo enforces BoringSSL's model. The defensible rationale: ACKs at epoch 0 are unprotected and trivially spoofable, so acting on them by immediately emitting traffic lets an off-path attacker pace your transmissions; keeping retransmission purely timer-driven bounds that. The ACK's essential function is to *prune* what gets retransmitted when the timer does fire — §5.8.1: "If the implementation has received one or more ACKs from the peer, then it SHOULD omit any messages or message fragments which have already been acknowledged."

(The RFC 9853 update to RFC 9147 only concerns return-routability checks for path migration — it doesn't touch ACK/retransmission behavior.)

**Bottom line for Botan:** treat received ACKs as purely subtractive state updates — never as send triggers. Retransmission should be driven exclusively by your retransmit timer, and the timer is cancelled only when the whole flight is acknowledged. That will satisfy `DTLS-Retransmit-Client-TLS13` and the related `ackFlightBasic`-based tests.

## User

So, does that mean that BoringSSL won't allow unauthenticated ACKs to trigger an immediate retransmission. That makes sense. But once the ACKs were transmitted within protected records, they would be authenticated. In such a case, would BoringSSL also wait for the next timer tick, or would it trigger a re-transmission immediately?

## Assistant

Let me verify there's no separate code path in BoringSSL that treats protected ACKs differently.

### Tool Ripgrep Raw Search

```
{"pattern":"dtls1_process_ack","path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl","outputMode":"content","caseInsensitive":false,"multiline":false,"toolCallId":"Grep_0_3b13e8aa-e3562","offset":0}
```

### Tool Ripgrep Raw Search

```
{"pattern":"dtls1_stop_timer|dtls1_start_timer|handle_timeout|retransmit","path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/d1_lib.cc","outputMode":"content","caseInsensitive":false,"headLimit":40,"multiline":false,"toolCallId":"Grep_1_8ba348e7-e3562","offset":0}
```

### Tool Read File V2

```
{"path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/d1_pkt.cc","offset":195,"limit":45}
```

### Tool Read File V2

```
{"path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/d1_both.cc","offset":395,"limit":45}
```

## Assistant

BoringSSL waits for the timer in that case too — ACK protection makes no difference to its retransmission behavior. The code confirms this unambiguously.

## Both ACK paths are the same, and neither sends anything

There are exactly two call sites for ACK processing — the handshake read path and the post-handshake/app-data path — and both funnel into the same function:

```419:420:build_deps/boringssl/ssl/d1_both.cc
    case SSL3_RT_ACK:
      return dtls1_process_ack(ssl, out_alert, record_number, record);
```

```219:220:build_deps/boringssl/ssl/d1_pkt.cc
  if (type == SSL3_RT_ACK) {
    return dtls1_process_ack(ssl, out_alert, record_number, record);
  }
```

And `dtls1_process_ack` (`d1_pkt.cc:35-158`) never branches on whether the ACK record *itself* arrived protected (epoch ≥ 2) or in plaintext (epoch 0). The only epoch logic in it is *validation of the acknowledged record numbers* — during the handshake, an ACK may not acknowledge records from a higher epoch than the ACK's own epoch (the errata eid8108 rule referenced at `d1_pkt.cc:70-80`). After that validation, protected and unprotected ACKs get identical treatment: mark messages ACKed; stop the timer if the flight is complete; otherwise just clear unused write epochs and leave the timer alone, with the unimplemented TODO to maybe schedule an earlier retransmit.

The only retransmission trigger in the whole stack is timer expiry in `DTLSv1_handle_timeout` (`d1_lib.cc:197-221`).

## Why not act on authenticated ACKs immediately?

Even though an epoch-2+ ACK is authenticated, immediate reaction buys little:

- **An on-path attacker controls delivery anyway.** They can drop, delay, or reorder packets, so they can already influence your retransmission timing. Authentication only excludes the *off-path* attacker — and the timer-based design already bounds that case.
- **One driver, one rate limit.** Keeping the retransmit timer as the sole send trigger keeps the state machine simple and guarantees retransmissions are always paced by the backoff schedule, regardless of what arrives from the network.
- The RFC's "SHOULD retransmit on partial ACK" (§5.8.1 exit 2, §7.2) is a loss-recovery *latency* optimization, not a correctness requirement. BoringSSL consciously trades it away — the TODO at `d1_pkt.cc:152-153` ("Schedule a retransmit. The peer will have waited before sending the ACK, so a partial ACK suggests packet loss.") shows they've considered reviving it as a *rescheduled timer*, not an immediate send.

## BoGo tests this exact case

Note that in `DTLS-Retransmit-Client-TLS13`, the partial ACK of your Finished flight is sent at the runner's current epoch — protected by then — and the test still demands silence until the timer fires:

```1181:1184:build_deps/boringssl/ssl/test/runner/dtls_tests.go
							// ACK part of the flight and check that retransmits
							// are updated.
							c.WriteACK(c.OutEpoch(), records[len(records)/3:2*len(records)/3])
							c.AdvanceClock(useTimeouts[1])
							records = c.ReadRetransmit()
```

`WriteACK(c.OutEpoch(), ...)` at that point emits an encrypted ACK record, and the subsequent `AdvanceClock` would still fail on any immediate retransmission. So for BoGo acceptance, the rule is unconditional: **ACKs only prune the retransmission queue; the timer alone drives retransmission** — regardless of whether the ACK arrived in a protected record.

## User

we're now exchanging application data. And then it appears that we're retransmitting our entire last flight, but the shim isn't happy about that. I'm guessing, the final Client-Finished and its respective ACK isn't handled correctly, yet.

## Assistant

Let me check how the runner tracks what your client is allowed to retransmit at each point, so I can map your symptom to the exact expectation.

### Tool Ripgrep Raw Search

```
{"pattern":"retransmitNeeded","path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/test/runner/dtls.go","outputMode":"content","caseInsensitive":false,"multiline":false,"toolCallId":"Grep_0_ed3659ea-a7b61","offset":0}
```

### Tool Read File V2

```
{"path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/test/runner/dtls.go","offset":875,"limit":70}
```

### Tool Read File V2

```
{"path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/test/runner/dtls.go","offset":1288,"limit":60}
```

## Assistant

Your guess is plausible, but let's pin it down precisely — "retransmitting the entire last flight" is only wrong at *some* points of this test, and actually **required** at one point. Here's the exact contract the runner enforces after your client sends its final flight, from the `ACKFlightDTLS` callback of `DTLS-Retransmit-Client-TLS13`:

```1165:1190:build_deps/boringssl/ssl/test/runner/dtls_tests.go
						ACKFlightDTLS: func(c *DTLSController, prev, received []DTLSMessage, records []DTLSRecordNumberInfo) {
							// The shim will process application data without an ACK.
							msg := []byte("hello")
							c.WriteAppData(c.OutEpoch(), msg)
							c.ReadAppData(c.InEpoch(), expectedReply(msg))

							// After a timeout, the shim will retransmit Finished.
							c.AdvanceClock(useTimeouts[0])
							c.ReadRetransmit()

							// Application data still flows.
							c.WriteAppData(c.OutEpoch(), msg)
							c.ReadAppData(c.InEpoch(), expectedReply(msg))

							// ACK part of the flight and check that retransmits
							// are updated.
							c.WriteACK(c.OutEpoch(), records[len(records)/3:2*len(records)/3])
							c.AdvanceClock(useTimeouts[1])
							records = c.ReadRetransmit()

							// ACK the rest. Retransmits should stop.
							c.WriteACK(c.OutEpoch(), records)
							for _, t := range useTimeouts[2:] {
								c.AdvanceClock(t)
							}
						},
```

Step by step:

1. **App data, no ACK** — the runner sends "hello" and expects just the echo. Your client must process app data while its final flight is still unacknowledged and send *nothing* else. Receipt of app data is **not** a retransmit trigger (the server may send half-RTT data before ever receiving your Finished — that's exactly what `DTLS-Retransmit-Client-NoImplictACKFinished` hammers on).
2. **First timeout** — *now* retransmitting the **entire** final flight is correct and expected; nothing has been ACKed yet.
3. **App data again** — must flow normally between retransmissions.
4. **Partial ACK (middle third of the records), then timeout** — now the retransmission must contain **only the un-ACKed records** (first and last thirds), in order.
5. **Full ACK** — cancel the retransmit timer; total silence through all remaining timeouts.

The runner enforces this with exact bookkeeping: `retransmitNeeded` is initialized from your received flight (`dtls.go:888-896`), `WriteACK` subtracts ACKed fragments from it (`dtls.go:1177-1221`), and `ReadRetransmit` matches your retransmission fragment-by-fragment against what remains (`dtls.go:1243-1308`).

## Mapping your symptom

Depending on *when* in this sequence the runner complains, the bug differs:

- **Fails at step 1 (during the first app-data exchange):** your client is treating inbound app data as a retransmit trigger. Check whether you implemented RFC 9147 §5.8.1's "receipt of application data with a new epoch ... retransmit their final flight immediately" clause — it does **not** apply here, because it's conditioned on "*prior to receipt of the corresponding Finished message*". Your client has already received the server's Finished (that's why it sent its own), so receiving epoch-3 app data must be a no-op for the retransmission state machine.
- **Fails at step 2:** retransmitting everything is right, so the complaint would be about *content* — e.g., stale records from the earlier ClientHello flight mixed in, or wrong epochs.
- **Fails at step 4 (after the partial ACK):** this matches your guess — the ACK for the final flight isn't pruning your retransmission queue. The runner expects exactly the un-ACKed remainder; sending the whole flight produces a fragment mismatch like "got offset X of message Y ..., expected ..." or "got excess data at epoch N in retransmit".
- **Fails at step 5:** the full ACK isn't cancelling your retransmit timer.

One more thing to verify in your implementation: the ACKs in steps 4–5 arrive at **epoch 3 (protected)** while acknowledging your **epoch 2** records — your ACK processing must match record numbers across epochs (ACK epoch ≥ acknowledged record epoch is legal; that's the eid8108 rule).

Can you paste the exact runner error text? "received N unexpected packets while simulating a timeout" points to a timing/trigger bug (steps 1 or 5), while "got offset ..."/"excess data" points to the pruning bug (step 4) — and I can help you narrow it further from there.

## User

I think I need some help understand the retransmission semantics: Let's say my initial transmission of my final flight (epoch=2) was in record sequence numbers 3,4,5,6. The first (full) retransmission will therefore retransmit in epoch=2, sequence numbers 7,8,9,10. Then there's the partial ACK from the runner: does this ACK (say) 3 and 4 or does it ACK 7, 8? And then, in the next retransmission, I'd retransmit partially with sequence numbers 11, 12. Will the final (full) ACK refer to any of those sequence numbers? I.e.: does my retransmission-queue have to keep taps on which record was retransmitted under which sequence numbers (i.e. 5, 9, and 11 for the third fragment)?

## Assistant

Excellent question — this gets at the core data structure you need. Short answer: **yes, you must track which record sequence numbers carried which message fragments across *all* transmissions of the flight.** Let me confirm the details in the RFC, the BoGo runner, and BoringSSL's implementation.

### Tool Ripgrep Raw Search

```
{"pattern":"struct DTLSSentRecord|DTLS_MAX_ACK_BUFFER|sent_records","path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/internal.h","outputMode":"content","contextAfter":12,"caseInsensitive":false,"headLimit":60,"multiline":false,"toolCallId":"Grep_0_d409d3d5-4f0a1","offset":0}
```

## Assistant

Yes — your parenthetical is exactly right. Let me walk through your scenario concretely, because the BoGo test deliberately exercises the trickiest version of it.

## The record layer vs. the message layer

The key mental model: **ACKs acknowledge *records* (by epoch + sequence number), but your retransmission state tracks *message fragments*.** You need a mapping between the two for every transmission still in play.

RFC 9147 confirms retransmissions get fresh record sequence numbers (§5.2):

> "When a message is retransmitted, the old message_seq value is reused, i.e., not incremented. From the perspective of the DTLS record layer, the retransmission is a new record. This record will have a new DTLSPlaintext.sequence_number value."

So your numbering is correct: 3,4,5,6 → 7,8,9,10 → 11,12, all at epoch 2.

## Which sequence numbers does the runner ACK?

Both kinds — and the test does it on purpose:

```1171:1186:build_deps/boringssl/ssl/test/runner/dtls_tests.go
							// After a timeout, the shim will retransmit Finished.
							c.AdvanceClock(useTimeouts[0])
							c.ReadRetransmit()
// ...
							// ACK part of the flight and check that retransmits
							// are updated.
							c.WriteACK(c.OutEpoch(), records[len(records)/3:2*len(records)/3])
							c.AdvanceClock(useTimeouts[1])
							records = c.ReadRetransmit()
```

- The **partial ACK** uses the `records` callback parameter — the record numbers of the **first transmission** (3,4,5,6 in your example). Note the first `ReadRetransmit()` *discards* its return value, so the ACK references records you already retransmitted as 7,8,9,10. This is legal: the receiver ACKs whichever transmission it received, and RFC 9147 §7.1 explicitly allows it to "acknowledge the records corresponding to each transmission of each flight or simply acknowledge the most recent one."
- The **final full ACK** uses the reassigned `records` — the record numbers of your **second (partial) retransmission** (11,12 in your example).

So in the test: partial ACK → {subset of 3,4,5,6}; final ACK → {11,12}. In the wild, any mix is possible, including an ACK for an old transmission arriving after you've already retransmitted (the ACK was in flight), or duplicate ACKs.

## The data structure you need

Yes — for the third fragment you keep tabs on 5, 9, *and* 11 until one of them is ACKed. When an ACK for record 5 arrives after you already re-sent that fragment as 9, you must still know which message bytes record 5 carried, mark them acknowledged, and exclude them from future retransmissions. The RFC calls this out directly (§7.2): "Note that this requires implementations to track which messages appear in which records."

BoringSSL's reference design:

```3174:3189:build_deps/boringssl/ssl/internal.h
// A DTLSSentRecord records information about a record we sent. Each record
// covers all bytes from |first_msg_start| (inclusive) of |first_msg| to
// |last_msg_end| (exclusive) of |last_msg|. Messages are referenced by index
// into |outgoing_messages|. |last_msg_end| may be |outgoing_messages.size()| if
// |last_msg_end| is zero.
// ...
struct DTLSSentRecord {
  DTLSRecordNumber number;
  PackedSize<SSL_MAX_HANDSHAKE_FLIGHT> first_msg = 0;
  PackedSize<SSL_MAX_HANDSHAKE_FLIGHT> last_msg = 0;
  uint32_t first_msg_start = 0;
  uint32_t last_msg_end = 0;
};
```

- Every sealed handshake record pushes a `DTLSSentRecord` onto a bounded MRU queue (`sent_records`, `DTLS_MAX_ACK_BUFFER = 32`) — see `d1_both.cc:831-841`.
- On ACK, the record number is looked up and the corresponding message byte ranges are marked acked (`d1_pkt.cc:82-120`).
- When the queue overflows, old entries are forgotten — and an ACK for a forgotten record is *not* an error, just ignored (`d1_pkt.cc:93-95`). Once a fragment is ACKed via any transmission, all its other record-number mappings become dead weight you can drop.

Two practical subtleties:

1. **Map to byte ranges, not whole messages.** A retransmission may fragment differently than the original (e.g., after an MTU change — BoGo's `DTLS-Retransmit-ChangeMTU` tests this), and the runner's `WriteACK` can prune *partial* fragments (`dtls.go:1183-1219`). BoringSSL's `first_msg_start`/`last_msg_end` offsets exist for exactly this reason.
2. **The mapping is per-flight.** When the flight is fully ACKed, drop the whole structure and stop the timer; when you send the next flight, you start fresh (sequence numbers keep incrementing within the epoch, of course).

So your retransmission queue is really two structures: the flight's messages/fragments with per-fragment "acked" bitmaps, plus the bounded record-number → fragment-range index that lets incoming ACKs find what to mark.

## User

So essentially, I could render all messages in a flight into their serialized byte streams (without fragmenting them and without marshalling them with fragment handshake layer headers). Then set up a bitmap over these rendered bytes for tracking the ACKs. And then just re-fragment each message taking previous ACKs into account.

## Assistant

Yes — that's a sound design, and it's essentially exactly what BoringSSL does. Let me verify the details against their implementation so you can see the few subtleties that matter.

### Tool Ripgrep Raw Search

```
{"pattern":"struct DTLSOutgoingMessage|acked|IsFullyAcked","path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/internal.h","outputMode":"content","contextBefore":2,"contextAfter":14,"caseInsensitive":false,"headLimit":60,"multiline":false,"toolCallId":"Grep_0_1e0bcbdf-351347","offset":0}
```

### Tool Ripgrep Raw Search

```
{"pattern":"acked\\.|FirstUnackedRange|unacked","path":"/home/meusel/Projects/botan/build_deps/boringssl/ssl/d1_both.cc","outputMode":"content","contextBefore":4,"contextAfter":10,"caseInsensitive":false,"headLimit":80,"multiline":false,"toolCallId":"Grep_0_f877cbd7-351348","offset":0}
```

## Assistant

Yes, that's precisely the right design — and it's exactly BoringSSL's architecture. Your proposal maps onto their structures one-to-one:

**Rendered messages + ACK bitmap** = `DTLSOutgoingMessage`:

```3101:3120:build_deps/boringssl/ssl/internal.h
struct DTLSOutgoingMessage {
  size_t msg_len() const {
    assert(!is_ccs);
    assert(data.size() >= DTLS1_HM_HEADER_LENGTH);
    return data.size() - DTLS1_HM_HEADER_LENGTH;
  }

  bool IsFullyAcked() const {
    // ACKs only exist in DTLS 1.3, which does not send ChangeCipherSpec.
    return !is_ccs && acked.IsComplete();
  }

  Array<uint8_t> data;
  uint16_t epoch = 0;
  bool is_ccs = false;
  // acked tracks which bits of the message have been ACKed by the peer. If
  // |msg_len| is zero, it tracks one bit for whether the header has been
  // received.
  DTLSMessageBitmap acked;
};
```

**Re-fragment at send time, skipping ACKed ranges** = their seal path:

```756:765:build_deps/boringssl/ssl/d1_both.cc
    // Iterate over every un-acked range in the message, if any.
    Span<const uint8_t> body = body_cbs;
    for (;;) {
      auto range = msg.acked.NextUnmarkedRange(ssl->d1->outgoing_offset);
      if (range.empty()) {
        // Advance to the next message.
        ssl->d1->outgoing_offset = 0;
        ssl->d1->outgoing_written++;
        break;
      }
```

A few details worth getting right:

1. **Keep the message header in the rendered bytes.** You need the fully rendered TLS-1.3-style message (type + uint24 length + body) anyway, because that's what feeds the transcript hash (RFC 9147 §5.2: the transcript is computed over the original Handshake messages *without* the DTLS `message_seq`/`fragment_offset`/`fragment_length` fields). The bitmap then only covers the body; the 12-byte DTLS fragment header is synthesized per fragment at send time.

2. **Zero-length bodies are an edge case.** A message with an empty body (e.g., an empty client Certificate) has no bytes to ACK, but you still need to track whether it was received — BoringSSL gives the bitmap one synthetic bit "for the header" in that case (`d1_both.cc:609-612`).

3. **Rendering once up front is not just convenient, it's a correctness aid.** RFC 9147 §5.5: "Senders MUST NOT change handshake message bytes upon retransmission." Receivers must handle arbitrary and overlapping fragment ranges, so your re-fragmentation boundaries may differ freely between transmissions (which is also how you handle BoGo's `DTLS-Retransmit-ChangeMTU` for free) — as long as the underlying bytes are identical.

4. **BoGo is strict about not re-sending ACKed bytes.** `doReadRetransmit` fails with "got %d bytes at offset %d of message %d but only %d bytes were missing" (`dtls.go:1289-1291`) if you retransmit already-ACKed ranges. It *does* tolerate you splitting the missing range into smaller fragments than the original transmission.

5. **You still need the second structure** from your previous question: the record-number → byte-range mapping (`DTLSSentRecord`) recorded every time you seal a record, so an incoming ACK for any transmission can find which bits to mark. One record may span fragments of several messages, so the mapping must cover a (first_msg, offset) → (last_msg, offset) range.

With that, the full-ACK check collapses to "all messages' bitmaps complete" → stop the timer, drop the flight state — which is exactly the `IsFullyAcked` loop you saw in `dtls1_process_ack`.
