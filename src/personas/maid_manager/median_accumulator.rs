// Copyright 2017 MaidSafe.net limited.
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

use lru_time_cache::LruCache;
use std::time::Duration;

pub struct MedianAccumulator<K> {
    quorum: usize,
    map: LruCache<K, Aggregate>,
}

impl<K> MedianAccumulator<K>
    where K: Clone + Ord
{
    pub fn new(quorum: usize, duration: Duration) -> Self {
        MedianAccumulator {
            quorum: quorum,
            map: LruCache::with_expiry_duration(duration),
        }
    }

    pub fn add(&mut self, key: K, value: u64) -> Option<u64> {
        let done = {
            let agg = self.map
                .entry(key.clone())
                .or_insert_with(Aggregate::new);
            agg.values.push(value);
            agg.values.len() >= self.quorum
        };

        if done {
            self.map.remove(&key).and_then(Aggregate::into_median)
        } else {
            None
        }
    }
}

struct Aggregate {
    values: Vec<u64>,
}

impl Aggregate {
    fn new() -> Self {
        Aggregate { values: Vec::new() }
    }

    fn into_median(mut self) -> Option<u64> {
        self.values.sort();
        match self.values.len() {
            0 => None,
            n if n % 2 != 0 => Some(self.values[n / 2]),
            n => {
                let v0 = self.values[(n / 2) - 1] as f64;
                let v1 = self.values[n / 2] as f64;
                Some(((v0 + v1) / 2.0).round() as u64)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke() {
        let mut accumulator = MedianAccumulator::new(5, Duration::from_secs(10));
        let msg_id = 0;

        assert_eq!(accumulator.add(msg_id, 1), None);
        assert_eq!(accumulator.add(msg_id, 2), None);
        assert_eq!(accumulator.add(msg_id, 3), None);
        assert_eq!(accumulator.add(msg_id, 4), None);
        assert_eq!(accumulator.add(msg_id, 5), Some(3));
    }
}
