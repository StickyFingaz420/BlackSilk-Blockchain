//! Build markers: test-only code compiled into a binary (W4-GUARD,
//! RT-STATEFUL).
//!
//! `cargo test` unifies the features of dev-dependencies into every binary
//! the same invocation builds: after `cargo test --release -p
//! blacksilk-node`, `target/release/blacksilk-node` has the `test-hooks`
//! code of chain, tx, px and p2p, at the path a
//! plain `cargo build --release` writes. That code is not inert (the chain
//! actor's linearization log grows without bound). A cargo-fuzz build
//! (`cfg(fuzzing)`) has fuzz-only code too, such as the transport's fixed
//! ephemeral secrets.
//!
//! Each such crate exports a marker that is `Some` only when its test code is
//! compiled in ([`TEST_HOOKS_MARKER`](crate::TEST_HOOKS_MARKER) and its
//! equivalents in tx, px and p2p), so the marker string is in a binary only
//! when the hooks are. [`BuildFlags`] collects them; the node, miner and
//! wallet print them in `--version` and at start-up, and refuse every network
//! but regtest while any is set ([`BuildFlags::check_network`]).
//! The node (its build script), the miner, the wallet and the genesis tool
//! (`compile_error!` in their crate roots) refuse to build with
//! `cfg(fuzzing)` at all.

use blacksilk_consensus::Network;

/// The marker of this crate's own `cfg(fuzzing)` code paths, and of every
/// crate built with the same flags (cargo-fuzz sets `--cfg fuzzing` for the
/// whole graph): `Some` only in a fuzz build.
#[cfg(fuzzing)]
pub const FUZZING_MARKER: Option<&str> = Some("+fuzzing:chain");
/// The marker of this crate's own `cfg(fuzzing)` code paths, and of every
/// crate built with the same flags (cargo-fuzz sets `--cfg fuzzing` for the
/// whole graph): `Some` only in a fuzz build.
#[cfg(not(fuzzing))]
pub const FUZZING_MARKER: Option<&str> = None;

/// The test-only code compiled into this build: one marker per crate whose
/// `test-hooks` feature or `cfg(fuzzing)` is set. Empty in a release build.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BuildFlags {
    markers: Vec<&'static str>,
}

impl BuildFlags {
    /// The markers of chain, tx and px (the crates every binary that links
    /// the chain layer has), and this crate's fuzz marker. Binaries add the
    /// markers of their other crates with [`BuildFlags::with`].
    pub fn of_chain_layer() -> Self {
        Self::default()
            .with(blacksilk_px::TEST_HOOKS_MARKER)
            .with(blacksilk_tx::TEST_HOOKS_MARKER)
            .with(crate::TEST_HOOKS_MARKER)
            .with(FUZZING_MARKER)
    }

    /// Adds a marker (`None`: that crate has no test code compiled in).
    pub fn with(mut self, marker: Option<&'static str>) -> Self {
        if let Some(m) = marker {
            if !self.markers.contains(&m) {
                self.markers.push(m);
            }
        }
        self
    }

    /// The markers, in the order they were added.
    pub fn markers(&self) -> &[&'static str] {
        &self.markers
    }

    /// No test-only code compiled in.
    pub fn is_clean(&self) -> bool {
        self.markers.is_empty()
    }

    /// The markers separated by spaces, empty for a clean build. Appended to
    /// the version line and the start-up log, so `--version` of a hooked
    /// binary always names its test code.
    pub fn render(&self) -> String {
        self.markers.join(" ")
    }

    /// ` <markers>` for a version line: empty for a clean build.
    pub fn suffix(&self) -> String {
        if self.is_clean() {
            String::new()
        } else {
            format!(" {}", self.render())
        }
    }

    /// `build flags: none`, or `build flags: <markers>`: the line binaries
    /// print in `--version` and at start-up.
    pub fn line(&self) -> String {
        if self.is_clean() {
            "build flags: none".to_string()
        } else {
            format!("build flags: {}", self.render())
        }
    }

    /// The `-V` and `--version` texts of a binary (after clap's program
    /// name): `<version> (commit <commit>)` with the markers appended, and
    /// `<version> (commit <commit>)` followed by the [`line`](Self::line), so
    /// `--version` of every BlackSilk binary has a `build flags:` line.
    pub fn version_texts(&self, version: &str, commit: &str) -> (String, String) {
        (
            format!("{version} (commit {commit}){}", self.suffix()),
            format!("{version} (commit {commit})\n{}", self.line()),
        )
    }

    /// Refuses every network but regtest for a build with test-only code:
    /// such a binary is for this repository's own tests, never for a shared
    /// network, evidence or genesis. `binary` names the program in the
    /// message.
    pub fn check_network(&self, binary: &str, network: Network) -> Result<(), String> {
        match network {
            Network::Regtest => Ok(()),
            Network::Testnet | Network::Mainnet if self.is_clean() => Ok(()),
            Network::Testnet | Network::Mainnet => Err(format!(
                "refusing to run on {}: this {binary} was built with test-only code ({}), \
                 which only regtest may use. It comes from a `cargo test` or fuzz build \
                 writing the binary; rebuild it with a plain `cargo build --release` from a \
                 clean commit (docs/testnet.md)",
                network_label(network),
                self.render()
            )),
        }
    }

    /// Refuses a build with test-only code on every network, regtest
    /// included: for runs whose output is evidence (`--require-clean-build`,
    /// [`REQUIRE_CLEAN_ENV`]) and for tools that make evidence or genesis
    /// material.
    pub fn check_clean(&self, binary: &str) -> Result<(), String> {
        if self.is_clean() {
            Ok(())
        } else {
            Err(format!(
                "refusing to run: this {binary} was built with test-only code ({}), and a \
                 clean build is required. It comes from a `cargo test` or fuzz build writing \
                 the binary; rebuild it with a plain `cargo build --release` from a clean \
                 commit (docs/testnet.md)",
                self.render()
            ))
        }
    }

    /// [`check_network`](Self::check_network), and with `require_clean`
    /// [`check_clean`](Self::check_clean) on every network.
    pub fn check_run(
        &self,
        binary: &str,
        network: Network,
        require_clean: bool,
    ) -> Result<(), String> {
        if require_clean {
            self.check_clean(binary)?;
        }
        self.check_network(binary, network)
    }
}

/// The environment equivalent of `--require-clean-build` (node, miner,
/// wallet, supply-audit): set to anything but empty or `0`, the binary
/// refuses test-only code on regtest too. A misspelt value requires a clean
/// build rather than silently allowing test code.
pub const REQUIRE_CLEAN_ENV: &str = "BLACKSILK_REQUIRE_CLEAN_BUILD";

/// Whether `value` (of [`REQUIRE_CLEAN_ENV`]) requires a clean build.
pub fn require_clean_value(value: Option<&std::ffi::OsStr>) -> bool {
    value.is_some_and(|v| !v.is_empty() && v != "0")
}

/// `--require-clean-build` given (`flag`), or [`REQUIRE_CLEAN_ENV`] set.
pub fn require_clean(flag: bool) -> bool {
    flag || require_clean_value(std::env::var_os(REQUIRE_CLEAN_ENV).as_deref())
}

fn network_label(n: Network) -> &'static str {
    match n {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
        Network::Regtest => "regtest",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Network; 3] = [Network::Mainnet, Network::Testnet, Network::Regtest];

    #[test]
    fn a_clean_build_runs_everywhere() {
        let f = BuildFlags::default().with(None).with(None);
        assert!(f.is_clean());
        assert_eq!(f.render(), "");
        assert_eq!(f.suffix(), "");
        for n in ALL {
            assert_eq!(f.check_network("node", n), Ok(()));
        }
    }

    #[test]
    fn a_hooked_build_runs_only_on_regtest() {
        for marker in ["+test-hooks:chain", "+fuzzing:p2p"] {
            let f = BuildFlags::default().with(None).with(Some(marker));
            assert!(!f.is_clean());
            assert_eq!(f.suffix(), format!(" {marker}"));
            assert_eq!(f.check_network("node", Network::Regtest), Ok(()));
            for n in [Network::Testnet, Network::Mainnet] {
                let e = f.check_network("node", n).unwrap_err();
                assert!(e.contains(marker), "{e}");
                assert!(e.contains(network_label(n)), "{e}");
            }
        }
    }

    /// `--require-clean-build`: a marked build is refused on regtest too; a
    /// clean build is never refused.
    #[test]
    fn a_clean_build_can_be_required() {
        let hooked = BuildFlags::default().with(Some("+test-hooks:tx"));
        for n in ALL {
            let e = hooked.check_run("node", n, true).unwrap_err();
            assert!(e.contains("+test-hooks:tx"), "{e}");
            assert_eq!(BuildFlags::default().check_run("node", n, true), Ok(()));
            assert_eq!(BuildFlags::default().check_run("node", n, false), Ok(()));
        }
        assert_eq!(hooked.check_run("node", Network::Regtest, false), Ok(()));
        assert!(hooked.check_run("node", Network::Testnet, false).is_err());
        assert!(hooked.check_clean("genesis").is_err());
        let v = |s: &str| require_clean_value(Some(std::ffi::OsStr::new(s)));
        assert!(!require_clean_value(None));
        assert!(!v("") && !v("0"));
        assert!(v("1") && v("yes") && v("true"));
        assert!(require_clean(true));
    }

    #[test]
    fn markers_keep_their_order_once_each() {
        let f = BuildFlags::default()
            .with(Some("+test-hooks:px"))
            .with(Some("+test-hooks:tx"))
            .with(Some("+test-hooks:px"));
        assert_eq!(f.markers(), ["+test-hooks:px", "+test-hooks:tx"]);
        assert_eq!(f.render(), "+test-hooks:px +test-hooks:tx");
    }

    /// The chain layer's markers are exactly the crates' features: this
    /// crate's own unit tests build it with `test-hooks` (the
    /// dev-dependency on itself), which enables tx's and px's.
    #[test]
    fn the_chain_layer_reports_its_crates() {
        let f = BuildFlags::of_chain_layer();
        assert_eq!(crate::TEST_HOOKS, cfg!(feature = "test-hooks"));
        assert_eq!(
            f.markers().contains(&"+test-hooks:chain"),
            crate::TEST_HOOKS
        );
        assert_eq!(
            f.markers().contains(&"+test-hooks:tx"),
            blacksilk_tx::TEST_HOOKS
        );
        assert_eq!(
            f.markers().contains(&"+test-hooks:px"),
            blacksilk_px::TEST_HOOKS
        );
        assert_eq!(f.markers().contains(&"+fuzzing:chain"), cfg!(fuzzing));
        assert!(f.check_network("node", Network::Regtest).is_ok());
    }
}
