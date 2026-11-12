"""The shared test vectors (sdk/vectors/vectors.json, made by the Rust core) - docs/10 §2.2."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from bridge4 import Agent, BridgeError, Content, Envelope, Identity, JoinLink, KeyCard, Puzzle, SignedRequest  # noqa
from bridge4 import Statement, canonical, check_federation, parse_strict  # noqa: E402
from bridge4 import crypto  # noqa: E402
from bridge4.encoding import b64, b64_var, base32  # noqa: E402

VECTORS = json.load(open(os.path.join(os.path.dirname(__file__), "..", "..", "vectors", "vectors.json"), encoding="utf-8"))


def identity(seed: int) -> Identity:
    return Identity(bytes([seed]) * 32, bytes([(seed + 100) % 256]) * 32)


class Json(unittest.TestCase):
    def test_canonical(self):
        for case in VECTORS["json"]["canonical"]:
            self.assertEqual(canonical(parse_strict(case["in"], 1 << 20)).decode("utf-8"), case["out"], case["in"])

    def test_invalid(self):
        for text in VECTORS["json"]["invalid"]:
            with self.assertRaises(BridgeError, msg=text):
                parse_strict(text, 1 << 20)
        for data in VECTORS["json"]["invalid_bytes_hex"]:
            with self.assertRaises(BridgeError):
                parse_strict(bytes.fromhex(data), 1 << 20)

    def test_size_first(self):
        with self.assertRaises(BridgeError) as caught:
            parse_strict(b"[" + b"1," * 100 + b"1]", 50)
        self.assertEqual(caught.exception.code, "TOO_LARGE")


class Encoding(unittest.TestCase):
    def test_base32_and_b64(self):
        for case in VECTORS["encoding"]["base32"]:
            self.assertEqual(base32(bytes.fromhex(case["hex"])), case["b32"])
        for case in VECTORS["encoding"]["b64"]:
            self.assertEqual(b64(bytes.fromhex(case["hex"])), case["b64"])
            self.assertEqual(b64_var(case["b64"], "x", 100).hex(), case["hex"])
        for text in VECTORS["encoding"]["b64_invalid"]:
            with self.assertRaises(BridgeError, msg=text):
                b64_var(text, "x", 100)


class Identities(unittest.TestCase):
    def test_cards_are_byte_exact(self):
        for case in VECTORS["identities"]["valid"]:
            ident = Identity(b64_var(case["sign_secret"], "s", 32), b64_var(case["box_secret"], "b", 32))
            self.assertEqual(b64(ident.sign_public), case["sign_public"])
            self.assertEqual(b64(ident.box_public), case["box_public"])
            self.assertEqual(ident.id, case["id"])
            tls = b64_var(case["tls"], "tls", 32) if case.get("tls") else None
            card = ident.key_card(case["role"], case.get("name"), case["iat"], case.get("urls"), tls)
            self.assertEqual(card.to_bytes().decode("utf-8"), case["card"])
            self.assertEqual(KeyCard.parse(case["card"].encode()).id, case["id"])

    def test_bad_cards(self):
        for case in VECTORS["identities"]["invalid"]:
            with self.assertRaises(BridgeError, msg=case["why"]):
                KeyCard.parse(case["card"].encode())


class Signatures(unittest.TestCase):
    def test_weak_keys_and_malleability(self):
        weak = VECTORS["signatures"]["weak_signature"]
        signature = b64_var(weak["sig"], "sig", 64)
        for key in VECTORS["signatures"]["weak_keys"]:
            with self.assertRaises(BridgeError):
                crypto.verify(b64_var(key, "k", 32), weak["domain"], weak["message"].encode(), signature)
        malleable = VECTORS["signatures"]["malleable"]
        statement = Statement.parse(malleable["statement"].encode())
        with self.assertRaises(BridgeError):
            statement.verify([KeyCard.parse(malleable["signer_card"].encode())], 1)


class Statements(unittest.TestCase):
    def test_signed_byte_exact(self):
        for case in VECTORS["statements"]["valid"]:
            signers = [identity(seed) for seed in case["signers"]]
            body = json.loads(case["body"])
            if len(signers) == 1:
                statement = Statement.sign(case["kind"], case["net"], case["iat"], case["exp"], body, signers[0])
            else:
                statement = Statement.sign_multi(case["kind"], case["net"], case["iat"], case["exp"], body, signers)
            self.assertEqual(statement.canonical_bytes().decode("utf-8"), case["statement"])
            self.assertEqual(statement.hash(), case["hash"])
            cards = [s.key_card("admin", None, 0) for s in signers]
            self.assertEqual(Statement.parse(case["statement"].encode()).verify(cards, len(cards)), [c.id for c in sorted(cards, key=lambda c: c.id)] if len(cards) > 1 else [cards[0].id])

    def test_bad_forms(self):
        for case in VECTORS["statements"]["invalid"]:
            with self.assertRaises(BridgeError, msg=case["why"]):
                Statement.parse(case["statement"].encode())


class Requests(unittest.TestCase):
    def test_request(self):
        case = VECTORS["request"]
        signer = identity(case["signer"])
        made = SignedRequest.sign(signer, case["aud"], case["op"], json.loads(case["body"]), case["iat"],
                                  b64_var(case["nonce"], "n", 16))
        self.assertEqual(made.to_bytes().decode("utf-8"), case["request"])
        card = signer.key_card("client", None, 0)
        parsed = SignedRequest.parse(case["request"].encode())
        parsed.check(case["aud"], case["iat"] + 1000)
        parsed.verify(card)
        with self.assertRaises(BridgeError):
            parsed.check(case["aud"], case["iat"] + 6 * 60 * 1000)
        with self.assertRaises(BridgeError):
            SignedRequest.parse(case["tampered"].encode()).verify(card)


class Contents(unittest.TestCase):
    def test_roundtrip_and_bad(self):
        for case in VECTORS["content"]["valid"]:
            self.assertEqual(Content.parse(case["content"].encode()).to_bytes().decode("utf-8"), case["content"])
        for text in VECTORS["content"]["invalid"]:
            with self.assertRaises(BridgeError, msg=text):
                Content.parse(text.encode())


class Envelopes(unittest.TestCase):
    def test_open_rust_envelopes(self):
        case = VECTORS["envelope"]
        sender, recipient = identity(case["sender"]), identity(case["recipient"])
        card = sender.key_card("client", None, 0)
        for data, dnet in ((case["plain"], None), (case["to_net"]["envelope"], case["to_net"]["dnet"])):
            envelope = Envelope.parse(data.encode())
            envelope.check_time(case["now"])
            self.assertEqual(envelope.dnet, dnet)
            self.assertEqual(envelope.open(recipient, card).decode("utf-8"), case["plaintext"])
            with self.assertRaises(BridgeError):
                envelope.open(sender, card)  # not the recipient
        for bad in case["invalid"]:
            envelope = Envelope.parse(bad["envelope"].encode())
            with self.assertRaises(BridgeError, msg=bad["why"]):
                envelope.open(recipient, card)

    def test_seal_and_open_here(self):
        alice, bob = identity(1), identity(2)
        bob_card, alice_card = bob.key_card("client", None, 0), alice.key_card("client", None, 0)
        net = identity(9).id
        envelope = Envelope.seal(alice, net, bob_card, b"hallo", 1000, 60)
        again = Envelope.seal(alice, net, bob_card, b"hallo", 1000, 60)
        self.assertNotEqual(envelope.to_bytes(), again.to_bytes(), "N1: new key and nonce every time")
        self.assertEqual(Envelope.parse(envelope.to_bytes()).open(bob, alice_card), b"hallo")


class Pow(unittest.TestCase):
    def test_puzzle(self):
        case = VECTORS["pow"]
        puzzle = Puzzle(json.loads(case["puzzle"]))
        puzzle.verify(KeyCard.parse(case["node_card"].encode()))
        self.assertEqual(b64(puzzle.solve(1 << 24)), case["solution"])
        self.assertTrue(puzzle.check_solution(b64_var(case["solution"], "s", 8)))


class Links(unittest.TestCase):
    def test_links(self):
        for case in VECTORS["links"]["valid"]:
            link = JoinLink.parse(case["link"])
            self.assertEqual((link.net, link.gateway, link.code, link.node), (case["net"], case["gateway"], case["code"], case["node"]))
            self.assertEqual(b64(link.tls) if link.tls else None, case["tls"])
        for text in VECTORS["links"]["invalid"]:
            with self.assertRaises(BridgeError, msg=text):
                JoinLink.parse(text)


class Agents(unittest.TestCase):
    def test_agent_statements(self):
        case = VECTORS["agents"]
        valid = case["valid"]
        agent = Agent.check(Statement.parse(valid["statement"].encode()), case["net"], case["now"])
        self.assertEqual((agent.agent, agent.owner.id, agent.note, agent.to, agent.rate, agent.scopes),
                         (valid["agent"], valid["owner"], valid["note"], valid["to"], valid["rate"], valid["scopes"]))
        self.assertEqual(agent.to_body(), Statement.parse(valid["statement"].encode()).body)
        for bad in case["invalid"]:
            with self.assertRaises(BridgeError, msg=bad["why"]):
                Agent.check(Statement.parse(bad["statement"].encode()), bad.get("net", case["net"]), bad.get("now", case["now"]))


class Federation(unittest.TestCase):
    def test_federation_proofs(self):
        case = VECTORS["federation"]
        master = KeyCard.parse(case["master"].encode())
        valid = case["valid"]
        self.assertTrue(check_federation(json.loads(valid["statement"]), case["net"], master, valid["peer"], case["now"]))
        for bad in case["invalid"]:
            self.assertFalse(check_federation(json.loads(bad["statement"]), case["net"], master, bad["peer"], case["now"]), bad["why"])


if __name__ == "__main__":
    unittest.main()
