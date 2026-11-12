"""Live test against a real node and a Rust echo client (tests/e2e `sdk-fixture`, docs/10 §2.3): join, send, open the
echo, task and response, an agent of ours, an agent of the echo client, revocation. Skipped without the fixture."""

import json
import os
import subprocess
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from bridge4 import Client, Content, Identity, NodeError  # noqa: E402

FIXTURE = os.environ.get("BRIDGE_FIXTURE") or os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "target", "debug", "sdk-fixture"
)


def receive_until(client, predicate, seconds=20):
    deadline = time.time() + seconds
    while time.time() < deadline:
        for message in client.receive(1).messages:
            if predicate(message):
                return message
    raise AssertionError("expected message did not arrive")


@unittest.skipUnless(os.path.exists(FIXTURE), "sdk-fixture not built (cargo build -p bridge-tests --bin sdk-fixture)")
class Live(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.process = subprocess.Popen([FIXTURE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        cls.info = json.loads(cls.process.stdout.readline())

    @classmethod
    def tearDownClass(cls):
        cls.process.stdin.close()
        cls.process.wait(timeout=30)

    def test_everything_against_rust(self):
        info = self.info
        alice = Client.join(Identity.generate(), info["link"])
        self.assertEqual(alice.net, info["net"])
        echo = alice.card_of(info["echo"])

        # Python seals, Rust opens and answers, Python opens.
        sent = alice.send(echo, "hallo aus Python – äöü 😀")
        answer = receive_until(alice, lambda m: m.sender == info["echo"])
        self.assertEqual(answer.content.text, "echo: hallo aus Python – äöü 😀")
        self.assertEqual(answer.content.reply, sent)
        self.assertIsNone(answer.agent_of)

        # Task and response.
        response = alice.request(echo, {"prompt": "Wie geht's?", "max_tokens": 5}, wait=20)
        self.assertIsNotNone(response)
        self.assertEqual(response.content.json(), {"prompt": "Wie geht's?", "max_tokens": 5})

        # Our own agent: limited to the echo client; Rust sees whom it acts for.
        key = Identity.generate()
        statement = alice.issue_agent(key.key_card("client", "Python-KI", 1), to=[info["echo"]], note="Python-KI")
        agent = Client(key, info["url"]).with_agent(statement).connect()
        agent.send(agent.card_of(info["echo"]), "von agent")
        echoed = receive_until(agent, lambda m: m.sender == info["echo"])
        self.assertEqual(echoed.content.text, f"echo: von agent [agent of {alice.identity.id}]")
        with self.assertRaises(NodeError) as refused:
            agent.send(agent.card_of(alice.identity.id), "an Alice")  # not in `to`
        self.assertEqual(refused.exception.code, "FORBIDDEN")

        # The echo client's agent writes to us: we see its owner.
        alice.send(echo, "agent-hello")
        hello = receive_until(alice, lambda m: m.sender == info["echo_agent"])
        self.assertEqual(hello.content.text, "hallo vom agent")
        self.assertEqual(hello.agent_of, (info["echo"], "Echo-Agent"))

        # Revoked: the agent's session ends.
        self.assertTrue(alice.revoke_agent(key.id))
        with self.assertRaises(NodeError) as gone:
            agent.receive(0)
        self.assertEqual(gone.exception.code, "NO_SESSION")


if __name__ == "__main__":
    unittest.main()
