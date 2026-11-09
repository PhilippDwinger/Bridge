//! Shared fixture for the bridge-net integration tests: a small network as the template builds it
//! (master key from 24 words, owner node = log operator = witness = gateway).
#![allow(dead_code)] // each test file uses a different part of the fixture

use bridge_core::{Id, Identity, KeyCard, Mnemonic, Role, Statement};
use bridge_net::{
    Applied, Body, Delegation, JoinMode, Log, Manifest, NetError, NetResult, NetState, Right, Rights, Seal, Service,
    Services,
};

/// Start time of every test network (ms).
pub const T0: i64 = 1_794_200_000_000;
/// One minute (ms).
pub const MIN: i64 = 60_000;
/// One day (ms).
pub const DAY: i64 = 86_400_000;
/// The official BIP-39 test words for entropy 0x00 * 32.
pub const ZERO_WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                              abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                              abandon art";

/// A deterministic identity per seed.
pub fn identity(seed: u8) -> Identity {
    Identity::from_secret_bytes(&[seed; 32], &[seed ^ 0x5a; 32])
}

/// A node card with one address.
pub fn node_card(node: &Identity, url: &str) -> NetResult<KeyCard> {
    Ok(node.key_card_with(Role::Node, None, &[url.to_string()], None, T0)?)
}

/// Shortcut for "this must have been skipped".
pub fn expect_skip(applied: Applied) -> NetResult<NetError> {
    match applied {
        Applied::Skipped(reason) => Ok(reason),
        Applied::Accepted => Err(NetError::BadFormat("expected the entry to be skipped, it was accepted".into())),
    }
}

/// A network under test: the log as the operator keeps it and the state computed from it.
pub struct Net {
    pub master: Identity,
    pub net: Id,
    pub owner: Identity,
    pub owner_card: KeyCard,
    pub log: Log,
    pub state: NetState,
}

impl Net {
    /// A network from the template with the owner node as start gateway (card included).
    pub fn new(mode: JoinMode) -> NetResult<Self> {
        Self::with(mode, |_| {})
    }

    /// Like [`Net::new`], with changes to the genesis manifest.
    pub fn with(mode: JoinMode, change: impl FnOnce(&mut Manifest)) -> NetResult<Self> {
        let master = Mnemonic::parse(ZERO_WORDS)?.to_identity()?;
        let net = master.id().clone();
        let owner = identity(1);
        let owner_card = node_card(&owner, "https://owner.example/n1")?;
        let master_card = master.key_card(Role::Net, Some("Testnetz"), T0)?;
        let mut manifest = Manifest::template(mode, "Testnetz", master_card, owner.id(), "https://owner.example/n1")?;
        manifest.gateways[0].card = Some(owner_card.clone());
        change(&mut manifest);
        let genesis = manifest.sign(&net, T0, T0 + 365 * DAY, &master)?;
        let mut log = Log::new(net.clone());
        log.append(&genesis)?;
        let state = NetState::genesis(&net, genesis.canonical_bytes())?;
        Ok(Self { master, net, owner, owner_card, log, state })
    }

    /// Signs with a lifetime of 30 days.
    pub fn sign<B: Body>(&self, body: &B, signer: &Identity, iat: i64) -> NetResult<Statement> {
        body.sign(&self.net, iat, iat + 30 * DAY, signer)
    }

    /// Signs by several signers with a lifetime of 30 days.
    pub fn sign_multi<B: Body>(&self, body: &B, signers: &[&Identity], iat: i64) -> NetResult<Statement> {
        body.sign_multi(&self.net, iat, iat + 30 * DAY, signers)
    }

    /// Appends to the log and replays it (like a careless log operator: no candidate check).
    pub fn push(&mut self, statement: &Statement) -> NetResult<Applied> {
        self.push_bytes(statement.canonical_bytes())
    }

    /// Appends raw bytes (a follower mirrors whatever the operator logged) and replays them.
    pub fn push_bytes(&mut self, bytes: &[u8]) -> NetResult<Applied> {
        self.log.append_bytes(bytes)?;
        Ok(self.state.apply(bytes))
    }

    /// The statement must be accepted.
    pub fn accept(&mut self, statement: &Statement) -> NetResult<()> {
        match self.push(statement)? {
            Applied::Accepted => Ok(()),
            Applied::Skipped(reason) => Err(reason),
        }
    }

    /// The statement must be skipped; returns why.
    pub fn skip(&mut self, statement: &Statement) -> NetResult<NetError> {
        expect_skip(self.push(statement)?)
    }

    /// The master delegates rights to the admin `seed`.
    pub fn delegate(&mut self, seed: u8, rights: &[Right], iat: i64) -> NetResult<Identity> {
        let admin = identity(seed);
        let body = Delegation {
            admin: admin.id().clone(),
            rights: Rights::of(rights),
            card: admin.key_card(Role::Admin, None, T0)?,
        };
        let statement = self.sign(&body, &self.master, iat)?;
        self.accept(&statement)?;
        Ok(admin)
    }

    /// A gateway seal body (level 2-3) for `node` with its card.
    pub fn gateway_seal(node: &Identity, level: u8) -> NetResult<Seal> {
        Ok(Seal {
            subject: node.id().clone(),
            level,
            services: Services::of(&[Service::Gateway]),
            card: Some(node_card(node, &format!("https://{}.example", node.id()))?),
        })
    }

    /// The master seals the owner node: level 3, gateway + log + witness.
    pub fn seal_owner(&mut self, iat: i64) -> NetResult<()> {
        let seal = Seal {
            subject: self.owner.id().clone(),
            level: 3,
            services: Services::of(&[Service::Gateway, Service::Log, Service::Witness]),
            card: Some(self.owner_card.clone()),
        };
        let statement = self.sign(&seal, &self.master, iat)?;
        self.accept(&statement)
    }

    /// The state replayed from scratch from the log.
    pub fn replayed(&self) -> NetResult<NetState> {
        NetState::replay(&self.net, self.log.entries())
    }
}
