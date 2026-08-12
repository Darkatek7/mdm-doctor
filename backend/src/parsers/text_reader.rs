use std::{
    borrow::Cow,
    fs::File,
    io::{BufRead, BufReader, Read, Seek, SeekFrom},
    path::Path,
};

use encoding_rs::WINDOWS_1252;

use crate::error::Result;

const SAMPLE_SIZE: usize = 4096;
const MAX_LINE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Encoding {
    Utf8,
    Utf16Le,
    Utf16Be,
    Windows1252,
}

pub struct DecodedLine {
    pub text: String,
    pub truncated: bool,
    pub replacements: usize,
}

pub struct DecodedLines {
    reader: BufReader<File>,
    encoding: Encoding,
    first_line: bool,
}

impl DecodedLines {
    pub fn open(path: &Path) -> Result<Self> {
        let mut file = File::open(path)?;
        let mut sample = vec![0_u8; SAMPLE_SIZE];
        let count = file.read(&mut sample)?;
        sample.truncate(count);
        let encoding = detect(&sample);
        file.seek(SeekFrom::Start(0))?;
        Ok(Self {
            reader: BufReader::with_capacity(128 * 1024, file),
            encoding,
            first_line: true,
        })
    }

    #[cfg(test)]
    fn encoding_name(&self) -> &'static str {
        match self.encoding {
            Encoding::Utf8 => "utf-8",
            Encoding::Utf16Le => "utf-16le",
            Encoding::Utf16Be => "utf-16be",
            Encoding::Windows1252 => "windows-1252",
        }
    }

    pub fn next_line(&mut self) -> Result<Option<DecodedLine>> {
        let mut line = match self.encoding {
            Encoding::Utf8 | Encoding::Windows1252 => self.read_single_byte_line()?,
            Encoding::Utf16Le | Encoding::Utf16Be => self.read_utf16_line()?,
        };
        if let Some(value) = &mut line
            && self.first_line
        {
            value.text = value.text.trim_start_matches('\u{feff}').to_owned();
        }
        self.first_line = false;
        Ok(line)
    }

    fn read_single_byte_line(&mut self) -> Result<Option<DecodedLine>> {
        let mut raw = Vec::new();
        if self.reader.read_until(b'\n', &mut raw)? == 0 {
            return Ok(None);
        }
        while raw.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
            raw.pop();
        }
        let truncated = raw.len() > MAX_LINE_BYTES;
        if truncated {
            raw.truncate(MAX_LINE_BYTES);
        }
        let (decoded, had_errors): (Cow<'_, str>, bool) = match self.encoding {
            Encoding::Utf8 => {
                let value = String::from_utf8_lossy(&raw);
                let errors = matches!(value, Cow::Owned(_));
                (value, errors)
            }
            Encoding::Windows1252 => WINDOWS_1252.decode_without_bom_handling(&raw),
            _ => unreachable!(),
        };
        let text = decoded.into_owned();
        Ok(Some(DecodedLine {
            replacements: if had_errors {
                text.matches('\u{fffd}').count().max(1)
            } else {
                0
            },
            text,
            truncated,
        }))
    }

    fn read_utf16_line(&mut self) -> Result<Option<DecodedLine>> {
        let mut units = Vec::new();
        let mut pair = [0_u8; 2];
        let mut truncated = false;
        loop {
            let first = self.reader.read(&mut pair[..1])?;
            if first == 0 {
                if units.is_empty() {
                    return Ok(None);
                }
                break;
            }
            if self.reader.read(&mut pair[1..])? == 0 {
                truncated = true;
                break;
            }
            let unit = match self.encoding {
                Encoding::Utf16Le => u16::from_le_bytes(pair),
                Encoding::Utf16Be => u16::from_be_bytes(pair),
                _ => unreachable!(),
            };
            if unit == 0x000a {
                break;
            }
            if units.len() < MAX_LINE_BYTES / 2 {
                units.push(unit);
            } else {
                truncated = true;
            }
        }
        if units.last() == Some(&0x000d) {
            units.pop();
        }
        let text = String::from_utf16_lossy(&units);
        Ok(Some(DecodedLine {
            replacements: text.matches('\u{fffd}').count(),
            text,
            truncated,
        }))
    }
}

fn detect(sample: &[u8]) -> Encoding {
    if sample.starts_with(&[0xff, 0xfe]) {
        return Encoding::Utf16Le;
    }
    if sample.starts_with(&[0xfe, 0xff]) {
        return Encoding::Utf16Be;
    }
    if sample.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Encoding::Utf8;
    }
    let pairs = sample.len() / 2;
    if pairs > 4 {
        let even_zero = sample.iter().step_by(2).filter(|b| **b == 0).count();
        let odd_zero = sample
            .iter()
            .skip(1)
            .step_by(2)
            .filter(|b| **b == 0)
            .count();
        if odd_zero * 3 > pairs {
            return Encoding::Utf16Le;
        }
        if even_zero * 3 > pairs {
            return Encoding::Utf16Be;
        }
    }
    if std::str::from_utf8(sample).is_ok() {
        return Encoding::Utf8;
    }
    Encoding::Windows1252
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn streams_utf16_and_windows_1252_lines() {
        let root = tempfile::tempdir().unwrap();
        let utf16 = root.path().join("utf16.txt");
        let mut bytes = vec![0xff, 0xfe];
        for unit in "Name=Contoso App\r\nError=0".encode_utf16() {
            bytes.extend(unit.to_le_bytes());
        }
        std::fs::write(&utf16, bytes).unwrap();
        let mut reader = DecodedLines::open(&utf16).unwrap();
        assert_eq!(reader.encoding_name(), "utf-16le");
        assert_eq!(
            reader.next_line().unwrap().unwrap().text,
            "Name=Contoso App"
        );

        let ansi = root.path().join("ansi.txt");
        let mut file = File::create(&ansi).unwrap();
        file.write_all(b"caf\xe9\n").unwrap();
        let mut reader = DecodedLines::open(&ansi).unwrap();
        assert_eq!(reader.encoding_name(), "windows-1252");
        assert_eq!(reader.next_line().unwrap().unwrap().text, "café");
    }

    #[test]
    fn detects_utf8_utf16be_and_nul_heuristics() {
        let root = tempfile::tempdir().unwrap();
        let utf8 = root.path().join("utf8.txt");
        std::fs::write(&utf8, "Policy=Geräteschutz\n").unwrap();
        let mut reader = DecodedLines::open(&utf8).unwrap();
        assert_eq!(reader.encoding_name(), "utf-8");
        assert_eq!(
            reader.next_line().unwrap().unwrap().text,
            "Policy=Geräteschutz"
        );

        let utf16be = root.path().join("utf16be.txt");
        let mut bytes = vec![0xfe, 0xff];
        for unit in "Profile=Secure Wi-Fi\n".encode_utf16() {
            bytes.extend(unit.to_be_bytes());
        }
        std::fs::write(&utf16be, bytes).unwrap();
        let mut reader = DecodedLines::open(&utf16be).unwrap();
        assert_eq!(reader.encoding_name(), "utf-16be");
        assert_eq!(
            reader.next_line().unwrap().unwrap().text,
            "Profile=Secure Wi-Fi"
        );

        let heuristic = root.path().join("heuristic.txt");
        let mut bytes = Vec::new();
        for unit in "Application=Company Portal\n".encode_utf16() {
            bytes.extend(unit.to_le_bytes());
        }
        std::fs::write(&heuristic, bytes).unwrap();
        let mut reader = DecodedLines::open(&heuristic).unwrap();
        assert_eq!(reader.encoding_name(), "utf-16le");
        assert_eq!(
            reader.next_line().unwrap().unwrap().text,
            "Application=Company Portal"
        );
    }

    #[test]
    fn bounds_long_and_malformed_lines() {
        let root = tempfile::tempdir().unwrap();
        let long = root.path().join("long.txt");
        let mut bytes = vec![b'x'; MAX_LINE_BYTES + 32];
        bytes.push(b'\n');
        std::fs::write(&long, bytes).unwrap();
        let mut reader = DecodedLines::open(&long).unwrap();
        let line = reader.next_line().unwrap().unwrap();
        assert!(line.truncated);
        assert_eq!(line.text.len(), MAX_LINE_BYTES);

        let malformed = root.path().join("malformed.txt");
        std::fs::write(&malformed, [0xff, 0xfe, b'A', 0, 0x00, 0xd8, b'x']).unwrap();
        let mut reader = DecodedLines::open(&malformed).unwrap();
        let line = reader.next_line().unwrap().unwrap();
        assert!(line.truncated);
        assert!(line.replacements >= 1);
    }
}
