use std::{
    fs::read_to_string,
    path::{Path, PathBuf},
    str::FromStr,
};

use nethsm::Passphrase;

/// A passphrase file error
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Path creation error
    #[error("Path error: {0}")]
    Path(#[from] core::convert::Infallible),
}

/// A representation of a file containing a passphrase
#[derive(Clone, Debug)]
pub struct PassphraseFile {
    pub passphrase: Passphrase,
}

impl PassphraseFile {
    pub fn new(path: &Path) -> Result<Self, Error> {
        Ok(Self {
            passphrase: Passphrase::new(read_to_string(path)?),
        })
    }
}

impl FromStr for PassphraseFile {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PassphraseFile::new(&PathBuf::from_str(s)?)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write;

    use rand::{Rng, thread_rng};
    use rstest::rstest;
    use testdir::testdir;
    use testresult::TestResult;

    use super::*;

    #[rstest]
    fn passphrase_file() -> TestResult {
        let mut i = 0;
        while i < 20 {
            let mut rng = thread_rng();
            let lines = rng.gen_range(0..20);
            let lines_vec = (0..lines)
                .map(|_x| "this is a passphrase".to_string())
                .collect::<Vec<String>>();
            let path = testdir!().join(format!("passphrase_file_lines_{lines}.txt"));
            let mut file = File::create(&path)?;
            file.write_all(lines_vec.join("\n").as_bytes())?;

            let passphrase_file = PassphraseFile::new(&path);
            assert!(passphrase_file.is_ok());
            i += 1;
        }

        Ok(())
    }
}
