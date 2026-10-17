//! `Policy::from_env`. Kept in its own test binary (its own process) because it changes
//! the process environment, which is only sound while no other thread reads it.
use grokbot_api::{ALLOW_LOCAL_ENV, Policy};

#[test]
fn from_env_reads_the_opt_in_variable() {
    let cases = [
        (None, false),
        (Some("1"), true),
        (Some(" TRUE "), true),
        (Some("yes"), true),
        (Some("0"), false),
        (Some("no"), false),
    ];
    for (value, want) in cases {
        // SAFETY: this binary has a single test, so no other thread touches the environment.
        unsafe {
            match value {
                Some(v) => std::env::set_var(ALLOW_LOCAL_ENV, v),
                None => std::env::remove_var(ALLOW_LOCAL_ENV),
            }
        }
        let p = Policy::from_env();
        assert_eq!(p.allow_local_gateway, want, "{value:?}");
        assert!(!p.allow_local_backend, "never enabled from the environment");
    }
}
