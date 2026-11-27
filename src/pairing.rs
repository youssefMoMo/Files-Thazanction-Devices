use data_encoding::BASE32_NOPAD;
use zeroize::Zeroizing;

use crate::AppResult;

/// A 256-bit, one-session pre-shared key. The printed code is a bearer secret:
/// anyone who obtains it can attempt to join the current receive session.
#[derive(Clone)]
pub struct PairingSecret(Zeroizing<[u8; 32]>);

impl PairingSecret {
    pub fn generate() -> AppResult<Self> {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        getrandom::fill(&mut bytes[..])?;
        Ok(Self(bytes))
    }

    pub fn from_code(code: &str) -> AppResult<Self> {
        // Keep temporary copies of the pairing secret in zeroizing containers.
        let normalized = Zeroizing::new(
            code.chars()
                .filter(|character| !character.is_whitespace() && *character != '-')
                .flat_map(char::to_uppercase)
                .collect::<String>(),
        );
        if normalized.len() != 52 {
            return Err(
                "pairing code must contain the 52 Base32 characters displayed by the receiver"
                    .into(),
            );
        }
        let decoded = Zeroizing::new(BASE32_NOPAD.decode(normalized.as_bytes())?);
        if decoded.len() != 32 {
            return Err("pairing code must decode to exactly 256 bits".into());
        }

        let mut key = Zeroizing::new([0_u8; 32]);
        key.copy_from_slice(decoded.as_slice());
        Ok(Self(key))
    }

    /// Encode the pairing secret into a displayable code whose temporary
    /// representation is zeroized when the caller drops it.
    pub fn to_code(&self) -> Zeroizing<String> {
        let encoded = Zeroizing::new(BASE32_NOPAD.encode(&self.0[..]));
        let mut code = Zeroizing::new(String::with_capacity(encoded.len() + 12));

        for (index, byte) in encoded.as_bytes().iter().enumerate() {
            if index > 0 && index % 4 == 0 {
                code.push('-');
            }
            code.push(char::from(*byte));
        }

        code
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::PairingSecret;

    #[test]
    fn pairing_code_round_trips() {
        let original = PairingSecret::generate().expect("secure random source available");
        let code = original.to_code();
        let restored = PairingSecret::from_code(code.as_str()).expect("generated code is valid");
        assert_eq!(original.as_bytes(), restored.as_bytes());
    }

    #[test]
    fn pairing_code_rejects_wrong_length() {
        assert!(PairingSecret::from_code("ABC123").is_err());
    }
}
