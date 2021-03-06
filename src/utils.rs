// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use crust::exe_file_stem;
use std::{env, process, sync};
use std::path::Path;

static HANDLE_VERSION: sync::Once = sync::ONCE_INIT;

pub fn handle_version() {
    HANDLE_VERSION.call_once(|| {
        let name = exe_file_stem().unwrap_or(Path::new("").to_path_buf());
        let name_and_version = format!("{} v{}", name.to_string_lossy(), env!("CARGO_PKG_VERSION"));
        if env::args().any(|arg| arg == "--version") {
            println!("{}", name_and_version);
            process::exit(0);
        }
        let message = String::from("Running ") + &name_and_version;
        let underline = String::from_utf8(vec!['=' as u8; message.len()]).unwrap();
        info!("\n\n{}\n{}", message, underline);
    });
}

#[cfg(test)]
pub fn generate_random_vec_u8(size: usize) -> Vec<u8> {
    use rand::random;
    let mut vec: Vec<u8> = Vec::with_capacity(size);
    for _ in 0..size {
        vec.push(random::<u8>());
    }
    vec
}
