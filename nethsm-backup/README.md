# NetHSM backup

A library to parse, decrypt, validate and browse NetHSM backups.

## Examples

Listing all fields in a backup file:

```rust no_run
# fn main() -> testresult::TestResult {
use std::collections::HashMap;

use nethsm_backup::Backup;

let backup = Backup::parse(std::fs::File::open("tests/nethsm.backup-file.bkp")?)?;
let decryptor = backup.decrypt(b"my-very-unsafe-backup-passphrase")?;

assert_eq!(decryptor.version()?, [0]);

for item in decryptor.items_iter() {
    let (key, value) = item?;
    println!("Found {key} with value: {value:X?}");
}
# Ok(()) }
```

Dumping the value of one specified field (here `/config/version`):

```rust no_run
# fn main() -> testresult::TestResult {
use std::collections::HashMap;

use nethsm_backup::Backup;

let backup = Backup::parse(std::fs::File::open("tests/nethsm.backup-file.bkp")?)?;
let decryptor = backup.decrypt(b"my-very-unsafe-backup-passphrase")?;

assert_eq!(decryptor.version()?, [0]);

for (key, value) in decryptor
    .items_iter()
    .flat_map(|item| item.ok())
    .filter(|(key, _)| key == "/config/version")
{
    println!("Found {key} with value: {value:X?}");
}
# Ok(()) }
```

## Contributing

Please refer to the [contributing guidelines] to learn how to contribute to this project.

## License

This project may be used under the terms of the [Apache-2.0] or [MIT] license.

Changes to this project - unless stated otherwise - automatically fall under the terms of both of the aforementioned licenses.

[Apache-2.0]: https://www.apache.org/licenses/LICENSE-2.0
[MIT]: https://opensource.org/licenses/MIT
[contributing guidelines]: ../CONTRIBUTING.md
