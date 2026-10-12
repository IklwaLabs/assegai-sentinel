//! Consent for active network response.
//!
//! # Why this gate exists
//!
//! Until v0.2, Sentinel only read. `SECURITY.md` guaranteed it: *"Sentinel does not modify
//! your network. It reads."* Active response breaks that guarantee, and the guarantee was
//! load-bearing -- it is a large part of why a cautious organisation would deploy this at all.
//!
//! The response layer is therefore opt-in in three separate ways, all of which must hold
//! before a single byte leaves the machine:
//!
//! 1. The operator states they are authorised for the network being defended. In many
//!    jurisdictions, injecting traffic onto a network you do not own is a criminal offence
//!    even when the traffic is corrective. This is not a disclaimer; it is the reason the
//!    other two conditions exist.
//! 2. The operator enables response explicitly. Default is off, and turning it on is not a
//!    side effect of upgrading.
//! 3. Every action is attributed to a named authoriser and recorded.
//!
//! A failed or absent consent never silently degrades to "detect only". It refuses, and says
//! why, because a user who thinks Sentinel is protecting them when it is not is worse off
//! than one who knows it refused.

use std::fmt;

/// A named authorisation to act on a specific network.
///
/// Serialised so it can be stored with the settings and shown again later: "who authorised
/// this, for what network, and when" is the first question asked after an automated action.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Authorization {
    /// Who accepted responsibility, as typed by the operator.
    #[serde(rename = "authorisedBy")]
    pub authorised_by: String,
    /// The network being defended, described in the operator's own words. Free text on
    /// purpose: Sentinel cannot verify ownership of a network, and pretending to by asking
    /// for a CIDR would imply a check it does not perform.
    #[serde(rename = "networkDescription")]
    pub network_description: String,
    /// When consent was given, as Unix microseconds.
    pub granted_at_us: u64,
}

/// Decides whether an action may be taken.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Consent {
    /// Response is disabled entirely. The default, and the state of every existing install.
    #[default]
    Disabled,
    /// Enabled with a stored authorisation.
    Granted(Box<Authorization>),
}

/// Why an action was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// Response is off. Nothing was attempted.
    #[error("active response is turned off, so nothing was changed on the network")]
    Disabled,
    /// Consent was granted but the stored authorisation is unusable.
    #[error("the stored authorisation is incomplete, so nothing was changed on the network")]
    IncompleteAuthorization,
}

impl Refusal {
    /// A message a person can act on, in the same voice as every other Sentinel error.
    #[must_use]
    pub fn guidance(&self) -> &'static [&'static str] {
        match self {
            Self::Disabled => &[
                "Active response is off. Turn it on in Settings if you own or are authorised to defend this network.",
                "Until then Sentinel still detects and reports, but will not modify anything.",
            ],
            Self::IncompleteAuthorization => &[
                "The saved authorisation is missing a name or a network description.",
                "Re-enter it in Settings. Sentinel will not act on a partial authorisation.",
            ],
        }
    }
}

/// Builds a valid authorisation, or explains precisely what was wrong with it.
///
/// Validated here rather than at the point of use, so an unusable authorisation can never be
/// persisted in the first place.
pub fn authorize(
    authorised_by: &str,
    network_description: &str,
    now_us: u64,
) -> Result<Authorization, Refusal> {
    let who = authorised_by.trim();
    let network = network_description.trim();

    if who.is_empty() || network.is_empty() {
        return Err(Refusal::IncompleteAuthorization);
    }

    Ok(Authorization {
        authorised_by: who.to_string(),
        network_description: network.to_string(),
        granted_at_us: now_us,
    })
}

/// Checks whether an action is permitted, and who permitted it.
///
/// Separate from [`Consent`] so the policy lives in one testable place rather than being
/// re-derived at each call site.
pub fn check(consent: &Consent) -> Result<&Authorization, Refusal> {
    match consent {
        Consent::Disabled => Err(Refusal::Disabled),
        Consent::Granted(authorization) => {
            if authorization.authorised_by.trim().is_empty()
                || authorization.network_description.trim().is_empty()
            {
                Err(Refusal::IncompleteAuthorization)
            } else {
                Ok(authorization)
            }
        }
    }
}

impl fmt::Display for Authorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} authorised Sentinel to act on {}",
            self.authorised_by, self.network_description
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_760_000_000_000_000;

    #[test]
    fn response_is_off_by_default() {
        // Every existing installation upgrades into this state, which is the point: turning
        // on packet injection must never be a side effect of upgrading.
        assert_eq!(Consent::default(), Consent::Disabled);
        assert_eq!(check(&Consent::default()), Err(Refusal::Disabled));
    }

    #[test]
    fn authorisation_is_trimmed() {
        let granted = authorize("  Eric  ", "  Office WiFi  ", NOW).expect("valid");
        assert_eq!(granted.authorised_by, "Eric");
        assert_eq!(granted.network_description, "Office WiFi");
    }

    #[test]
    fn a_blank_name_is_refused_at_authorisation_time() {
        // Refused when it is created, so a partial authorisation is never persisted and
        // cannot later be discovered as a surprising refusal mid-incident.
        assert_eq!(
            authorize("   ", "Office WiFi", NOW),
            Err(Refusal::IncompleteAuthorization)
        );
        assert_eq!(
            authorize("Eric", "  ", NOW),
            Err(Refusal::IncompleteAuthorization)
        );
    }

    #[test]
    fn a_tampered_authorisation_is_caught_at_use() {
        // Defence in depth: even if an incomplete record reaches storage, acting on it is
        // refused rather than treated as consent.
        let broken = Authorization {
            authorised_by: String::new(),
            network_description: "Office WiFi".to_string(),
            granted_at_us: NOW,
        };
        assert_eq!(
            check(&Consent::Granted(Box::new(broken))),
            Err(Refusal::IncompleteAuthorization)
        );
    }

    #[test]
    fn granted_consent_permits_and_names_the_authoriser() {
        let granted = authorize("Eric", "Office WiFi", NOW).expect("valid");
        let consent = Consent::Granted(Box::new(granted));
        let who = check(&consent).expect("permitted");
        assert_eq!(who.authorised_by, "Eric");
    }

    #[test]
    fn every_refusal_carries_actionable_guidance() {
        for refusal in [Refusal::Disabled, Refusal::IncompleteAuthorization] {
            assert!(
                !refusal.guidance().is_empty(),
                "{refusal} must tell the user what to do, not only what happened"
            );
        }
    }

    #[test]
    fn a_refusal_names_the_setting_to_change() {
        assert!(
            Refusal::Disabled
                .guidance()
                .iter()
                .any(|hint| hint.contains("Settings")),
            "the user has to be told where the switch is"
        );
    }
}
