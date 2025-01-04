use memchr;

pub struct Scanner {
    bytes: Vec<u8>,
    signatures: Vec<Signature>,
    wildcard: String
}

impl Scanner {
    pub fn new(file: &[u8], wildcard: &str) -> Self {
        Scanner {
            bytes: file.to_vec(),
            signatures: Vec::new(),
            wildcard: String::from(wildcard)
        }
    }

    pub fn add_signature(&mut self, signature: &str) {
        if signature.len() == 0 {
            return;
        }

        self.signatures
            .push(Signature::new(signature, self.wildcard.as_str()).to_decimal());
    }

    pub fn scan(&mut self) -> Vec<u64> {
        let mut addresses = Vec::new();

        for signature in self.signatures.iter() {
            let (needle, offset) = signature.into_needle();
            memchr::memmem::find_iter(&self.bytes, &needle.as_slice()).for_each(|i| {
                let index = i - offset as usize;
                if signature.match_bytes(&self.bytes[index..index + (signature.len() as usize)]) {
                    addresses.push(index as u64);
                }
            });
        }

        self.bytes.clear();
        self.signatures.clear();

        addresses
    }
}

struct Signature {
    raw: String,
    wildcard: String
}

impl Signature {
    fn new(raw: &str, wildcard: &str) -> Self {
        Signature {
            raw: String::from(raw),
            wildcard: String::from(wildcard)
        }
    }

    fn len(&self) -> u64 {
        self.raw.split_whitespace().count() as u64
    }

    fn get(&self, index: u64) -> Option<String> {
        if index >= self.len() {
            return None;
        }

        let mut split_signature = self.raw.split_whitespace();
        split_signature.nth(index as usize).map(|s| s.to_string())
    }

    fn to_decimal(&mut self) -> Self {
        let mut new_signature = String::new();

        let split_signature = self.raw.split_whitespace();
        for c in split_signature.into_iter() {
            if c == self.wildcard {
                new_signature.push_str(c);
            } else {
                new_signature.push_str(u8::from_str_radix(c, 16).unwrap().to_string().as_str());
            }

            new_signature.push_str(" ");
        }

        new_signature.pop();
        Self {
            raw: new_signature,
            wildcard: self.wildcard.clone()
        }
    }

    fn into_needle(&self) -> (Vec<u8>, u64) {
        let split_signature: Vec<&str> = self.raw.split(self.wildcard.as_str()).collect();

        let (position, _) = split_signature
            .iter()
            .enumerate()
            .max_by_key(|(_, segment)| segment.chars().filter(|c| c.is_whitespace()).count())
            .unwrap_or((0, &""));

        let wildcard_count = position as u64;

        let token_count = split_signature[..position]
            .iter()
            .flat_map(|s| s.split_whitespace())
            .count() as u64;

        let offset = token_count + wildcard_count;

        let needle = split_signature[position]
            .split_whitespace()
            .map(|s| u8::from_str_radix(s, 10).unwrap())
            .collect();

        (needle, offset)
    }

    fn match_bytes(&self, bytes: &[u8]) -> bool {
        if self.len() != bytes.len() as u64 {
            return false;
        }

        bytes.iter().enumerate().all(|(i, &byte)| {
            let signature_byte = self.get(i as u64);
            if signature_byte.is_none() {
                return false;
            }

            let signature_byte = signature_byte.unwrap();
            if signature_byte == self.wildcard {
                true
            } else {
                signature_byte
                    .parse::<u8>()
                    .map(|parsed_byte| parsed_byte == byte)
                    .unwrap_or(false)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_length() {
        let signatures = vec![
            "00 00 ? 10 10 10 10 ? ? 255",
            "10 20 30 ? 00",
            "00 00 ? ? 0 0 0 ? 1 1 1 1 1 1 ?",
        ];

        let mut results = vec![10, 5, 15].into_iter();
        for signature in signatures {
            let signature = Signature::new(signature, "?");
            assert_eq!(signature.len(), results.next().unwrap());
        }
    }

    #[test]
    fn test_signature_get() {
        let signatures = vec!["E3 DD 00 ? ? ? 4B", "FF D3 BC 00 ? 0A ? 4D"];

        let mut results = vec![
            vec!["E3", "DD", "00", "?", "?", "?", "4B"],
            vec!["FF", "D3", "BC", "00", "?", "0A", "?", "4D"],
        ]
        .into_iter();

        for signature in signatures {
            let signature = Signature::new(signature, "?");

            let result = results.next().unwrap();
            for i in 0..signature.len() {
                assert_eq!(
                    signature.get(i),
                    Some(result.get(i as usize).unwrap().to_string())
                );
            }
        }
    }

    #[test]
    fn test_signature_into_needle() {
        let signatures = vec![
            "00 00 ? 10 10 10 10 ? ?",
            "10 20 30 ? 00",
            "00 00 ? ? 0 0 0 ? 1 1 1 1 1 1",
        ];

        let mut results = vec![
            (vec![10, 10, 10, 10], 3),
            (vec![10, 20, 30], 0),
            (vec![1, 1, 1, 1, 1, 1], 8),
        ]
        .into_iter();

        for signature in signatures {
            let signature = Signature::new(signature, "?");
            let (needle, offset) = signature.into_needle();
            assert_eq!((needle, offset), results.next().unwrap());
        }
    }

    #[test]
    fn test_signature_to_decimal() {
        let signatures = vec!["FF E3 DD 00 ? ? ? 4B"];

        let mut results = vec!["255 227 221 0 ? ? ? 75"].into_iter();

        for signature in signatures {
            let signature = Signature::new(signature, "?").to_decimal();
            assert_eq!(signature.raw, results.next().unwrap());
        }
    }

    #[test]
    fn test_match_bytes() {
        let signatures = vec![
            "FF E3 DD 00 ? ? ? 4B",
            "0A 14 1E ? 00 0A 14 1E 28 32 ? 0A",
            "FF ? FF ? 00 00 AA AA AA ? BB",
        ];

        let mut bytes = vec![
            vec![255, 227, 221, 0, 100, 100, 100, 75],
            vec![10, 20, 30, 100, 0, 10, 20, 30, 40, 50, 100, 10],
            vec![
                255, 100, 255, 100, 0, 0, 170, 170, 170, 100, 187, 100, 100, 100,
            ],
        ]
        .into_iter();

        for signature in signatures {
            let signature = Signature::new(signature, "?").to_decimal();

            let (_needle, _offset) = signature.into_needle();
            assert_eq!(
                signature.match_bytes(&bytes.next().unwrap()[..signature.len() as usize]),
                true
            );
        }
    }

    #[test]
    fn test_scanner() {
        let bytes = vec![
            0xFF, 0xE3, 0xDD, 0x0, 100, 100, 100, 0x4B, 0x0A, 0x14, 0x1E, 100, 0x0, 0x0A, 0x14,
            0x1E, 0x28, 0x32, 100, 0x0A, 0xFF, 100, 0xFF, 100, 0x0, 0x0, 0xAA, 100, 0xBB, 0xAA,
            0xCC, 0xDD,
        ];

        let mut scanner = Scanner::new(&bytes, "?");
        scanner.add_signature("FF E3 DD 00 ? ? ? 4B");
        scanner.add_signature("0A 14 1E ? 00 0A 14 1E 28 32 ? 0A");
        scanner.add_signature("FF ? FF ? 00 00 AA AA AA ? BB");

        let result = scanner.scan();
        assert_eq!(result, vec![0, 8]);
    }
}
