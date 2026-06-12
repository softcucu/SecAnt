import asyncio
import unittest

from proto_vuln_hunt import events as EV
from proto_vuln_hunt.events import EventBus
from proto_vuln_hunt.pipeline import Pipeline
from proto_vuln_hunt.config import Config


class EventBusPersistTests(unittest.TestCase):
    def _bus(self):
        sunk = []
        bus = EventBus(sink=sunk.append)
        return bus, sunk

    def test_persisted_event_goes_to_sink_and_backlog(self):
        bus, sunk = self._bus()
        bus.emit(EV.ROUND_START, {"round": 1})  # 默认 persist=True
        self.assertEqual(len(sunk), 1)
        self.assertEqual(len(bus.events), 1)

    def test_output_chunk_not_persisted_and_not_in_backlog(self):
        bus, sunk = self._bus()
        bus.emit(EV.AGENT_UPDATE, {"status": "output", "chunk": "x" * 100000}, persist=False)
        # 不落盘、不进内存 backlog
        self.assertEqual(sunk, [])
        self.assertEqual(bus.events, [])
        # 但 seq 仍递增(实时推送可用)
        self.assertEqual(bus.last_seq, 1)

    def test_non_persisted_event_still_reaches_live_subscriber(self):
        async def run():
            bus, _sunk = self._bus()
            received = []

            async def consume():
                async for ev in bus.stream(last_id=0):
                    received.append(ev)
                    if ev["type"] == EV.AGENT_UPDATE:
                        return

            task = asyncio.create_task(consume())
            await asyncio.sleep(0.01)  # 让订阅者先挂上
            bus.emit(EV.AGENT_UPDATE, {"status": "output", "chunk": "live"}, persist=False)
            await asyncio.wait_for(task, timeout=1.0)
            return received

        received = asyncio.run(run())
        self.assertTrue(any(ev["type"] == EV.AGENT_UPDATE for ev in received))


class RecordAgentWiringTests(unittest.TestCase):
    def _pipeline(self):
        captured = []
        cfg = Config(target=".", models={"audit": ["m"]})
        cfg.health.enabled = False
        pipe = Pipeline(cfg, emitter=lambda etype, data, persist=True: captured.append((etype, persist)))
        return pipe, captured

    def test_output_status_is_not_persisted(self):
        pipe, captured = self._pipeline()
        pipe.record_agent({"id": "a1", "status": "output", "chunk": "abc"})
        # 只发一条 AGENT_UPDATE,persist=False,且不附带 METRICS
        self.assertEqual(captured, [(EV.AGENT_UPDATE, False)])

    def test_non_output_status_is_persisted(self):
        pipe, captured = self._pipeline()
        pipe.record_agent({"id": "a1", "status": "done"})
        # AGENT_UPDATE 持久化,且跟一条 METRICS
        self.assertIn((EV.AGENT_UPDATE, True), captured)
        self.assertTrue(any(etype == EV.METRICS for etype, _ in captured))


if __name__ == "__main__":
    unittest.main()
