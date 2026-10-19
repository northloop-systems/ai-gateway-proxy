//! The username and password exchange.
//!
//! RFC 1929, and nothing else. There is no "no authentication" here: the
//! proxy sits on the node's tunnel and the hub is the only thing that is
//! supposed to use it, but the hub authenticates anyway, so that a mistake
//! in the tunnel's configuration cannot turn the node into an open relay.

/// Check the username/password exchange. Returns true when the
/// credentials are right.
pub fn check(user: &str, password: &str, offered_user: &[u8], offered_pass: &[u8]) -> bool {
    // Both halves are always compared, so the time the check takes says
    // nothing about which half was wrong.
    same(user.as_bytes(), offered_user) & same(password.as_bytes(), offered_pass)
}

/// Compare two byte strings without letting the time taken give the answer
/// away: a password that is right up to the last byte must not take longer
/// to reject than one that is wrong at the first.
fn same(expected: &[u8], offered: &[u8]) -> bool {
    let mut difference = u8::from(expected.len() != offered.len());
    for index in 0..expected.len().min(offered.len()) {
        difference |= expected[index] ^ offered[index];
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::check;

    #[test]
    fn the_right_credentials_pass() {
        assert!(check(
            "proxyuser",
            "s3cret-pass-value",
            b"proxyuser",
            b"s3cret-pass-value"
        ));
    }

    #[test]
    fn the_wrong_password_fails() {
        assert!(!check(
            "proxyuser",
            "s3cret-pass-value",
            b"proxyuser",
            b"wrong"
        ));
    }

    #[test]
    fn the_wrong_username_fails() {
        assert!(!check(
            "proxyuser",
            "s3cret-pass-value",
            b"nobody",
            b"s3cret-pass-value"
        ));
    }

    #[test]
    fn a_prefix_is_not_a_match() {
        // The password is longer than what was offered: that is a different
        // password, not the same one that got cut short.
        assert!(!check(
            "proxyuser",
            "s3cret-pass-value",
            b"proxyuser",
            b"s3cret"
        ));
        assert!(!check(
            "proxyuser",
            "s3cret-pass-value",
            b"proxy",
            b"s3cret-pass-value"
        ));
    }

    #[test]
    fn empty_credentials_are_only_right_when_configured_empty() {
        assert!(check("", "", b"", b""));
        assert!(!check("proxyuser", "s3cret-pass-value", b"", b""));
        assert!(!check("proxyuser", "s3cret-pass-value", b"proxyuser", b""));
    }

    #[test]
    fn bytes_that_are_not_text_are_not_a_match() {
        // The credentials are compared as bytes, so a client that sends
        // something that is not the password is refused, whatever it is.
        assert!(!check(
            "proxyuser",
            "s3cret-pass-value",
            b"\xff\xfe",
            b"s3cret-pass-value"
        ));
    }
}
