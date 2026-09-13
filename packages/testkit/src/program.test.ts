import {describe,expect,it} from "vitest";
import {J} from "./prelude.mts";
import {EXCHANGE_SPECS,PEER_TRANSCRIPT_SPECS,collectPeerTranscript,createExchangeCollector} from "./harness.ts";

// The spec's concatenated evaluation program, run in-process: §8.2 + §13.1
// (module init), then the 58 §3.3 exchanges, then the six §4.4 transcripts —
// all sharing one exchange-id sequence, every printed line round-tripping.
describe("concatenated evaluation program", () => {
  it("runs all 58 exchanges then all 6 peer transcripts without throwing", () => {
    const collector = createExchangeCollector();
    expect(EXCHANGE_SPECS).toHaveLength(58);
    EXCHANGE_SPECS.forEach((spec, i) => {
      const out = collector.exchange(spec.method, spec.params, spec.result, spec.peer ?? false);
      expect(out.request.id).toBe("q" + String(i + 1));
      expect(out.response.id).toBe(out.request.id);
      // expectedResult round-trips through canonical J form
      expect(J(JSON.parse(J(spec.result)))).toBe(J(spec.result));
      expect(J(JSON.parse(J(spec.params)))).toBe(J(spec.params));
      // the recorded {request,response,headers?} prints and round-trips
      const line = J(out);
      expect(J(JSON.parse(line))).toBe(line);
    });
    expect(collector.entries).toHaveLength(58);

    expect(PEER_TRANSCRIPT_SPECS).toHaveLength(6);
    for (const t of PEER_TRANSCRIPT_SPECS) {
      const lines = collectPeerTranscript(t.family, t.transport, t.session, collector);
      expect(lines).toHaveLength(11);
      expect(JSON.parse(lines[0]!).connector).toEqual({ family: t.family, transport: t.transport, provider_session: t.session });
      for (const line of lines) expect(J(JSON.parse(line))).toBe(line);
    }
    // 58 §3.3 exchanges + 6 transcripts x 10 exchanges each, sharing q1..q118
    expect(collector.entries).toHaveLength(118);
    expect(collector.entries[117]!.request.id).toBe("q118");
  });
});
